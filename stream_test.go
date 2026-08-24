package main

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// 端到端流式测试辅助：mock 上游按给定方式回写 SSE，网关反向还原。
// ---------------------------------------------------------------------------

// newE2EUpstream 构造一个 fake 上游：读取网关脱敏后的请求，提取其中的占位符，
// 交给 gen(phs) 生成要回写的 SSE 行（自动处理 flush）。
func newE2EUpstream(gen func(phs []string) []string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		phs := placeholderRe.FindAllString(string(b), -1)
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		flusher, _ := w.(http.Flusher)
		for _, ln := range gen(phs) {
			fmt.Fprintln(w, ln)
			if flusher != nil {
				flusher.Flush()
			}
		}
	}))
}

// runGatewayE2E 起一个网关，POST 客户端请求，返回还原后的完整响应体。
func runGatewayE2E(t *testing.T, upstream *httptest.Server, clientBody string) string {
	t.Helper()
	old := appCfg.Target()
	appCfg.SetTarget(upstream.URL)
	defer func() { _ = appCfg.SetTarget(old) }()

	gw := httptest.NewServer(http.HandlerFunc(handleProxy))
	defer gw.Close()

	req, _ := http.NewRequest("POST", gw.URL+"/v1/chat/completions", strings.NewReader(clientBody))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return string(out)
}

// sseContent 生成一条包含指定 content 值的 data 行。
func sseContent(v string) string {
	return `data: {"choices":[{"delta":{"content":"` + v + `"}}]}`
}

// ---------------------------------------------------------------------------
// 大模型流式返回的各种形态
// ---------------------------------------------------------------------------

// 占位符被模型逐字拆到每个 data 行（最极端情况），必须跨行完整还原。
func TestE2EStreamCharwiseSplit(t *testing.T) {
	ResetPIIStore()
	body := `{"messages":[{"role":"user","content":"电话13811223344"}]}`
	up := newE2EUpstream(func(phs []string) []string {
		var lines []string
		for _, ch := range phs[0] {
			lines = append(lines, sseContent(string(ch)))
		}
		lines = append(lines, sseContent("，请保密"))
		lines = append(lines, "data: [DONE]")
		return lines
	})
	out := runGatewayE2E(t, up, body)
	if !strings.Contains(out, "13811223344") {
		t.Fatalf("charwise split not restored: %s", out)
	}
	if strings.Contains(out, "<<PII:") || strings.Contains(out, "<<PI") || strings.Contains(out, "<<P") {
		t.Fatalf("placeholder leaked: %s", out)
	}
	if !strings.Contains(out, "请保密") {
		t.Fatalf("trailing text lost: %s", out)
	}
}

// 占位符被拆成多个不定长片段（3 字符一块），跨多个 data 行还原。
func TestE2EStreamMultiChunk(t *testing.T) {
	ResetPIIStore()
	body := `{"messages":[{"role":"user","content":"身份证110101199003071234"}]}`
	up := newE2EUpstream(func(phs []string) []string {
		ph := phs[0]
		var lines []string
		for i := 0; i < len(ph); i += 3 {
			end := i + 3
			if end > len(ph) {
				end = len(ph)
			}
			lines = append(lines, sseContent(ph[i:end]))
		}
		lines = append(lines, "data: [DONE]")
		return lines
	})
	out := runGatewayE2E(t, up, body)
	if !strings.Contains(out, "110101199003071234") {
		t.Fatalf("multi-chunk split not restored: %s", out)
	}
	if strings.Contains(out, "<<PII:") || strings.Contains(out, "<<PI") {
		t.Fatalf("placeholder leaked: %s", out)
	}
}

// 流式包含大量非 content 行（role / 空 content / finish_reason / usage / [DONE]），
// 这些行应原样透传，不影响 content 还原。
func TestE2EStreamNonContentLines(t *testing.T) {
	ResetPIIStore()
	body := `{"messages":[{"role":"user","content":"号码13855667788"}]}`
	up := newE2EUpstream(func(phs []string) []string {
		return []string{
			`data: {"choices":[{"delta":{"role":"assistant"}}]}`,
			sseContent("你的电话是" + phs[0]),
			`data: {"choices":[{"delta":{"content":""}}]}`,
			`data: {"choices":[{"delta":{"finish_reason":"stop"}}]}`,
			`data: {"usage":{"total_tokens":42}}`,
			"data: [DONE]",
		}
	})
	out := runGatewayE2E(t, up, body)
	if !strings.Contains(out, "13855667788") {
		t.Fatalf("not restored: %s", out)
	}
	if strings.Contains(out, "<<PII:") || strings.Contains(out, "<<PI") {
		t.Fatalf("placeholder leaked: %s", out)
	}
	if !strings.Contains(out, "total_tokens") {
		t.Fatalf("usage line lost: %s", out)
	}
}

// 一条消息里同时出现多个 PII，生成多个占位符，流式回显需全部还原。
func TestE2EStreamMultiplePlaceholders(t *testing.T) {
	ResetPIIStore()
	body := `{"messages":[{"role":"user","content":"手机13866778899，身份证110101199003071234"}]}`
	up := newE2EUpstream(func(phs []string) []string {
		if len(phs) < 2 {
			t.Fatalf("expected 2 placeholders, got %d: %v", len(phs), phs)
		}
		return []string{
			sseContent("手机是" + phs[0] + "，证件" + phs[1] + "已登记"),
			"data: [DONE]",
		}
	})
	out := runGatewayE2E(t, up, body)
	for _, p := range []string{"13866778899", "110101199003071234"} {
		if !strings.Contains(out, p) {
			t.Fatalf("not restored %s: %s", p, out)
		}
	}
	if strings.Contains(out, "<<PII:") || strings.Contains(out, "<<PI") {
		t.Fatalf("placeholder leaked: %s", out)
	}
}

// content 值一开始就是占位符（占位符在行首），也要正常还原。
func TestE2EStreamPlaceholderAtStart(t *testing.T) {
	ResetPIIStore()
	body := `{"messages":[{"role":"user","content":"验证码15912345678"}]}`
	up := newE2EUpstream(func(phs []string) []string {
		return []string{
			sseContent(phs[0] + "是您的验证码"),
			"data: [DONE]",
		}
	})
	out := runGatewayE2E(t, up, body)
	if !strings.Contains(out, "15912345678") {
		t.Fatalf("placeholder-at-start not restored: %s", out)
	}
	if strings.Contains(out, "<<PII:") {
		t.Fatalf("placeholder leaked: %s", out)
	}
}

// 流式内容里包含多个连续占位符（如两个 PII 紧挨着），都要还原且不串。
func TestE2EStreamAdjacentPlaceholders(t *testing.T) {
	ResetPIIStore()
	body := `{"messages":[{"role":"user","content":"手机13877889900身份证110101199003071234"}]}`
	up := newE2EUpstream(func(phs []string) []string {
		if len(phs) < 2 {
			t.Fatalf("expected 2 placeholders, got %d", len(phs))
		}
		return []string{
			sseContent("号码" + phs[0] + phs[1] + "确认"),
			"data: [DONE]",
		}
	})
	out := runGatewayE2E(t, up, body)
	if !strings.Contains(out, "13877889900") || !strings.Contains(out, "110101199003071234") {
		t.Fatalf("adjacent placeholders not restored: %s", out)
	}
	if strings.Contains(out, "<<PII:") {
		t.Fatalf("placeholder leaked: %s", out)
	}
}

// 流式被上游截断：最后一行 content 只有占位符的开头（如 [[），流就结束。
// 未闭合前缀应透传给客户端（内容不丢），且不 panic、不无限等待。
func TestE2EStreamTrailingDangling(t *testing.T) {
	ResetPIIStore()
	body := `{"messages":[{"role":"user","content":"测试15098765432"}]}`
	up := newE2EUpstream(func(phs []string) []string {
		// 只输出 content 值为 "[[" 的一行后结束（模拟被切断）
		return []string{sseContent("前缀" + "[[" )}
	})
	out := runGatewayE2E(t, up, body)
	// 未闭合前缀应被透传（不丢内容）
	if !strings.Contains(out, "[[") {
		t.Fatalf("dangling prefix lost: %q", out)
	}
	if !strings.Contains(out, "前缀") {
		t.Fatalf("leading text lost: %q", out)
	}
}

// 上游回显普通文本（非 SSE），网关应退化处理，不阻塞。
func TestE2EStreamPlainTextFallback(t *testing.T) {
	ResetPIIStore()
	body := `{"messages":[{"role":"user","content":"手机13888990011"}]}`
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		ph := placeholderRe.FindString(string(b))
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "收到%s", ph)
	}))
	defer up.Close()
	out := runGatewayE2E(t, up, body)
	if !strings.Contains(out, "13888990011") {
		t.Fatalf("plain-text fallback not restored: %s", out)
	}
	if strings.Contains(out, "<<PII:") {
		t.Fatalf("placeholder leaked: %s", out)
	}
}

// 模型把占位符的 < > 输出成 JSON 转义形式(\u003c \u003e)，例如
// "\u003c\u003cPII:NAME:31\u003e\u003e"，且被拆到多个 data 行。
// 网关必须先反转义再跨行拼接，否则 carry 无法积累，占位符还原失败。
func TestE2EStreamEscapedPlaceholderCharwise(t *testing.T) {
	ResetPIIStore()
	body := `{"messages":[{"role":"user","content":"手机13888990011"}]}`
	up := newE2EUpstream(func(phs []string) []string {
		ph := phs[0] // 例如 <<PII:PHONE:1>>
		// 转义尖括号；\u003c / \u003e 是完整转义序列(模型不会拆开)，普通字符逐字拆
		escaped := strings.ReplaceAll(ph, "<", `\u003c`)
		escaped = strings.ReplaceAll(escaped, ">", `\u003e`)
		var chunks []string
		for i := 0; i < len(escaped); {
			if strings.HasPrefix(escaped[i:], `\u`) {
				chunks = append(chunks, escaped[i:i+6])
				i += 6
			} else {
				chunks = append(chunks, escaped[i:i+1])
				i++
			}
		}
		var lines []string
		for _, c := range chunks {
			lines = append(lines, sseContent(c))
		}
		lines = append(lines, sseContent("，请保密"))
		lines = append(lines, "data: [DONE]")
		return lines
	})
	out := runGatewayE2E(t, up, body)
	if !strings.Contains(out, "13888990011") {
		t.Fatalf("escaped placeholder not restored: %s", out)
	}
	if strings.Contains(out, `\u003c`) || strings.Contains(out, `\u003e`) {
		t.Fatalf("escaped seq leaked: %s", out)
	}
	if strings.Contains(out, "<<PII:") || strings.Contains(out, "<<PI") || strings.Contains(out, "<<P") {
		t.Fatalf("placeholder leaked: %s", out)
	}
	if !strings.Contains(out, "请保密") {
		t.Fatalf("trailing text lost: %s", out)
	}
}

// 转义占位符以不定长片段输出。\u003c / \u003e 是完整转义序列（模型不会拆开），
// 因此把每个转义序列当整体，其余单字符按不定长分组，模拟真实分块。
func TestE2EStreamEscapedPlaceholderMultiChunk(t *testing.T) {
	ResetPIIStore()
	body := `{"messages":[{"role":"user","content":"电话0755-12345678"}]}`
	up := newE2EUpstream(func(phs []string) []string {
		ph := phs[0] // 例如 <<PII:LANDLINE:1>>
		escaped := strings.ReplaceAll(ph, "<", `\u003c`)
		escaped = strings.ReplaceAll(escaped, ">", `\u003e`)
		// 按转义序列整体 + 普通字符分组（转义序列不分拆）
		var parts []string
		for i := 0; i < len(escaped); {
			if strings.HasPrefix(escaped[i:], `\u`) {
				parts = append(parts, escaped[i:i+6]) // \u003c / \u003e 共6字符
				i += 6
			} else {
				parts = append(parts, escaped[i:i+1])
				i++
			}
		}
		// 合并成若干不定长块（每块 1~4 个逻辑单元）
		var merged []string
		for i := 0; i < len(parts); {
			n := 1 + i%4
			end := i + n
			if end > len(parts) {
				end = len(parts)
			}
			merged = append(merged, strings.Join(parts[i:end], ""))
			i = end
		}
		var lines []string
		for _, p := range merged {
			lines = append(lines, sseContent(p))
		}
		lines = append(lines, "data: [DONE]")
		return lines
	})
	out := runGatewayE2E(t, up, body)
	if !strings.Contains(out, "0755-12345678") {
		t.Fatalf("escaped multi-chunk not restored: %s", out)
	}
	if strings.Contains(out, `\u003c`) || strings.Contains(out, "<<PII:") || strings.Contains(out, "<<PI") {
		t.Fatalf("placeholder leaked: %s", out)
	}
}
