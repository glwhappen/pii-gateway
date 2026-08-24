package main

import (
	"strconv"
	"strings"
	"testing"
)

func TestMaskAndRestore(t *testing.T) {
	ResetPIIStore()
	body := `{"messages":[{"role":"user","content":"我叫张三，电话13812345678，身份证110101199003071234，另一个号15098765432。"}]}`
	m := newMapping()
	masked := mask([]byte(body), m)

	// 原始 PII 不应再出现在掩码结果里
	for _, pii := range []string{"13812345678", "110101199003071234", "15098765432"} {
		if strings.Contains(string(masked), pii) {
			t.Fatalf("PII not masked: %s in %s", pii, masked)
		}
	}
	// 应有占位符
	if !strings.Contains(string(masked), "[[PID_") {
		t.Fatalf("no placeholder produced: %s", masked)
	}

	// 还原应恢复原文
	restored := restore(masked, m)
	for _, pii := range []string{"13812345678", "110101199003071234", "15098765432"} {
		if !strings.Contains(string(restored), pii) {
			t.Fatalf("PII not restored: %s in %s", pii, restored)
		}
	}
	// 还原后不应残留占位符
	if strings.Contains(string(restored), "[[PID_") {
		t.Fatalf("placeholder leaked after restore: %s", restored)
	}
	if string(restored) != string(body) {
		t.Fatalf("roundtrip mismatch:\n got: %s\nwant: %s", restored, body)
	}
}

func TestMaskStripsHeaderPseudonymButKeepsJSON(t *testing.T) {
	ResetPIIStore()
	// 占位符不应破坏 JSON 结构（引号/冒号/括号保持原样）
	body := `{"user":"13800001111","age":30}`
	m := newMapping()
	masked := mask([]byte(body), m)
	s := string(masked)
	if !strings.HasPrefix(s, `{"user":"[[PID_`) {
		t.Fatalf("JSON structure broken: %s", s)
	}
	restored := restore([]byte(s), m)
	if string(restored) != body {
		t.Fatalf("roundtrip mismatch: %s != %s", restored, body)
	}
}

// 同一内容（同一手机号/身份证）跨请求必须复用同一占位符；不同内容必须不同。
func TestDeterministicMapping(t *testing.T) {
	ResetPIIStore()

	m1 := newMapping()
	ph1 := string(mask([]byte("13812345678"), m1))

	m2 := newMapping()
	ph2 := string(mask([]byte("13812345678"), m2))

	if ph1 != ph2 {
		t.Fatalf("same PII got different placeholders: %q vs %q", ph1, ph2)
	}
	// 各自都能还原
	if string(restore([]byte(ph1), m1)) != "13812345678" {
		t.Fatalf("restore via m1 failed")
	}
	if string(restore([]byte(ph2), m2)) != "13812345678" {
		t.Fatalf("restore via m2 failed")
	}

	// 不同 PII 占位符必须不同
	m3 := newMapping()
	ph3 := string(mask([]byte("13999999999"), m3))
	if ph3 == ph1 {
		t.Fatalf("different PII got same placeholder: %q", ph3)
	}

	// 同一请求内同一内容出现多次，MaskedCount 只计 1
	m4 := newMapping()
	masked4 := mask([]byte("号码13812345678，另一个也13812345678"), m4)
	if m4.MaskedCount() != 1 {
		t.Fatalf("expected 1 unique PII, got %d in %s", m4.MaskedCount(), masked4)
	}
	// 且还原能还原所有出现位置
	restored4 := string(restore(masked4, m4))
	if !strings.Contains(restored4, "13812345678") {
		t.Fatalf("restore failed: %s", restored4)
	}
}

// 手动添加映射 + 落盘 + 重启加载：同一真实值保持同一占位符。
func TestPersistAndManualAdd(t *testing.T) {
	tdir := t.TempDir()
	storeFile := tdir + "/store.json"

	old := piiStoreFile
	piiStoreFile = storeFile
	defer func() { piiStoreFile = old }()

	ResetPIIStore()

	// 手动添加
	ph, ok := globalStore.lookup("1111")
	if ok {
		t.Fatalf("1111 should not exist yet")
	}
	n := pidCounter.Add(1)
	ph = "[[PID_" + strconv.FormatUint(n, 10) + "]]"
	globalStore.remember("1111", ph)
	if err := globalStore.saveFile(storeFile); err != nil {
		t.Fatal(err)
	}

	// 模拟重启：重置 store 并从文件加载
	ResetPIIStore()
	if err := globalStore.loadFile(storeFile); err != nil {
		t.Fatal(err)
	}

	// 重启后 1111 仍在，且占位符一致
	got, ok := globalStore.lookup("1111")
	if !ok {
		t.Fatalf("1111 not persisted after reload")
	}
	if got != ph {
		t.Fatalf("placeholder changed after reload: %s vs %s", got, ph)
	}

	// mask 遇到 1111 复用同一占位符
	m := newMapping()
	masked := mask([]byte("内容 1111 其他"), m)
	if !strings.Contains(string(masked), ph) {
		t.Fatalf("1111 not masked to persisted placeholder %s: %s", ph, masked)
	}
}

func TestRestoreStreamLine(t *testing.T) {
	ResetPIIStore()
	// 模拟 SSE 中占位符跨行不发生时，单行还原
	m := newMapping()
	masked := mask([]byte("13812345678"), m)
	ph := string(masked)
	line := "data: {\"choices\":[{\"delta\":{\"content\":\"" + ph + "\"}}]}"
	out := restore([]byte(line), m)
	if !strings.Contains(string(out), "13812345678") {
		t.Fatalf("stream line not restored: %s", out)
	}
	if strings.Contains(string(out), "[[PID_") {
		t.Fatalf("stream line leaked placeholder: %s", out)
	}
}

// 占位符可能被拆在任何位置（[[PID_ 锚点本身都可能被拆断），
// 且流式下每个 data 行的 content 是独立 token，restoreContent 必须跨 content 拼接还原。
func TestRestoreLineSplitPlaceholder(t *testing.T) {
	cases := []struct {
		name   string
		chunks []string // 按行拆分的 content 值片段
	}{
		{"无拆分", []string{"[[PID_1]]", "再来"}},
		{"拆在[[PID_", []string{"[[PID_", "1]]", "再来"}},
		{"拆在[[PI", []string{"[[PI", "D_1]]", "再来"}},
		{"拆在[[", []string{"[[", "PID_1]]", "再来"}},
		{"单字符逐字拆", []string{"[", "[", "P", "I", "D", "_", "1", "]", "]", "再来"}},
		{"拆在数字中", []string{"[[PID_1", "]]", "再来"}},
		{"拆在闭合括号", []string{"[[PID_1", "]", "]", "再来"}},
		{"多占位符+尾部未闭合", []string{"甲[[PID_1]]乙[[PI", "D_2]]丙"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := newMapping()
			m.real["[[PID_1]]"] = "13811112222"
			m.real["[[PID_2]]"] = "13933334444"

			var carry string
			var sb strings.Builder
			for _, c := range tc.chunks {
				out, next := restoreContent(c, m, carry)
				carry = next
				sb.WriteString(out)
			}
			if carry != "" {
				t.Fatalf("unexpected carry left: %q", carry)
			}
			got := sb.String()
			// 必须完整还原，且不残留占位符
			if !strings.Contains(got, "13811112222") {
				t.Fatalf("PID_1 not restored: %q", got)
			}
			if strings.Contains(got, "[[PID_") {
				t.Fatalf("placeholder leaked: %q", got)
			}
			if !strings.Contains(got, "再来") && strings.Contains(tc.chunks[len(tc.chunks)-1], "再来") {
				t.Fatalf("trailing text lost: %q", got)
			}
		})
	}
}

// 验证 findClosingQuote 能跳过转义引号，正确取出 content 值。
func TestFindClosingQuote(t *testing.T) {
	s := `"content":"他说\"好\"，电话[[PID_1]]"}}]`
	i := strings.Index(s, `"content":"`) + len(`"content":"`)
	e := findClosingQuote(s, i)
	got := s[i:e]
	want := `他说\"好\"，电话[[PID_1]]`
	if got != want {
		t.Fatalf("findClosingQuote got %q want %q", got, want)
	}
}
