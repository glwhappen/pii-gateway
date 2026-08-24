package main

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestEndToEndStream 模拟完整链路：
// 客户端发含 PII 请求 -> 网关脱敏 -> mock new-api 收到占位符 -> 返回 SSE(回显占位符) -> 网关还原 -> 客户端拿到真实 PII。
func TestEndToEndStream(t *testing.T) {
	var upstreamGot string
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		upstreamGot = string(b)
		// 上游绝不能看到真实手机号
		if strings.Contains(upstreamGot, "13812345678") {
			t.Errorf("PII leaked to upstream: %s", upstreamGot)
		}
		ph := placeholderRe.FindString(upstreamGot)
		if ph == "" {
			t.Errorf("no placeholder sent upstream: %s", upstreamGot)
		}
		// 返回 SSE，回显占位符
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		flusher, _ := w.(http.Flusher)
		fmt.Fprintf(w, "data: {\"choices\":[{\"delta\":{\"content\":\"你好，我的电话是%s\"}}]}\n\n", ph)
		flusher.Flush()
		fmt.Fprintf(w, "data: {\"choices\":[{\"delta\":{\"content\":\"请保密。\"}}]}\n\n")
		flusher.Flush()
		fmt.Fprintf(w, "data: [DONE]\n\n")
		flusher.Flush()
	}))
	defer fake.Close()

	old := appCfg.Target()
	appCfg.SetTarget(fake.URL)
	defer func() { _ = appCfg.SetTarget(old) }()

	gw := httptest.NewServer(http.HandlerFunc(handleProxy))
	defer gw.Close()

	req, _ := http.NewRequest("POST", gw.URL+"/v1/chat/completions",
		strings.NewReader(`{"messages":[{"role":"user","content":"我的电话是13812345678"}]}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer sk-xxx")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	s := string(out)

	// 客户端必须拿到还原后的真实手机号
	if !strings.Contains(s, "13812345678") {
		t.Fatalf("stream not restored, got: %s", s)
	}
	if strings.Contains(s, "[[PID_") {
		t.Fatalf("placeholder leaked to client: %s", s)
	}
}

// TestEndToEndStreamSplit 模拟占位符被模型拆到相邻两个 data 行，
// 网关必须跨行拼接还原，不能把半截占位符发给客户端。
func TestEndToEndStreamSplit(t *testing.T) {
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		ph := placeholderRe.FindString(string(b))
		if ph == "" {
			t.Errorf("no placeholder sent upstream: %s", b)
		}
		// 把占位符拆成两个 data 行：[[PI | D_1]]
		split := len(ph) / 2
		half1 := ph[:split]
		half2 := ph[split:]
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		flusher, _ := w.(http.Flusher)
		fmt.Fprintf(w, "data: {\"choices\":[{\"delta\":{\"content\":\"我的电话是%s\"}}]}\n\n", half1)
		flusher.Flush()
		fmt.Fprintf(w, "data: {\"choices\":[{\"delta\":{\"content\":\"%s，请保密。\"}}]}\n\n", half2)
		flusher.Flush()
		fmt.Fprintf(w, "data: [DONE]\n\n")
		flusher.Flush()
	}))
	defer fake.Close()

	old := appCfg.Target()
	appCfg.SetTarget(fake.URL)
	defer func() { _ = appCfg.SetTarget(old) }()

	gw := httptest.NewServer(http.HandlerFunc(handleProxy))
	defer gw.Close()

	req, _ := http.NewRequest("POST", gw.URL+"/v1/chat/completions",
		strings.NewReader(`{"messages":[{"role":"user","content":"我的电话是13812345678"}]}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	s := string(out)

	if !strings.Contains(s, "13812345678") {
		t.Fatalf("split placeholder not restored: %s", s)
	}
	if strings.Contains(s, "[[PID_") || strings.Contains(s, "[[PI") {
		t.Fatalf("placeholder leaked across chunks: %s", s)
	}
}

// TestEndToEndNonStream 非流式场景验证。
func TestEndToEndNonStream(t *testing.T) {
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		if strings.Contains(string(b), "110101199003071234") {
			t.Errorf("id card leaked upstream: %s", b)
		}
		ph := placeholderRe.FindString(string(b))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"choices":[{"message":{"content":"你的证件%s已登记"}}]}`, ph)
	}))
	defer fake.Close()

	old := appCfg.Target()
	appCfg.SetTarget(fake.URL)
	defer func() { _ = appCfg.SetTarget(old) }()

	gw := httptest.NewServer(http.HandlerFunc(handleProxy))
	defer gw.Close()

	req, _ := http.NewRequest("POST", gw.URL+"/v1/chat/completions",
		strings.NewReader(`{"messages":[{"role":"user","content":"我的身份证是110101199003071234"}]}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	s := string(out)
	if !strings.Contains(s, "110101199003071234") {
		t.Fatalf("non-stream not restored: %s", s)
	}
	if strings.Contains(s, "[[PID_") {
		t.Fatalf("placeholder leaked: %s", s)
	}
}
