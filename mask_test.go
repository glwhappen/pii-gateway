package main

import (
	"strings"
	"testing"
)

func TestMaskAndRestore(t *testing.T) {
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

func TestRestoreStreamLine(t *testing.T) {
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
