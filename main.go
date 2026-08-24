package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

var (
	// 由 appCfg.load() / applyConfig 在启动时设置
	listenAddr = ":3001"
)

// hop-by-hop 头不能透传
var hopHeaders = map[string]bool{
	"Connection":          true,
	"Proxy-Connection":    true,
	"Keep-Alive":          true,
	"Proxy-Authenticate":  true,
	"Proxy-Authorization": true,
	"Te":                  true,
	"Trailer":             true,
	"Transfer-Encoding":   true,
	"Upgrade":             true,
	"Host":                true,
	// 我们会改写响应体，长度会变化，不能透传上游 Content-Length
	"Content-Length": true,
}

func main() {
	appCfg.load()
	if err := globalStore.loadFile(piiStoreFile); err != nil {
		log.Printf("load pii store %s: %v", piiStoreFile, err)
	}
	if err := globalRules.load(); err != nil {
		log.Printf("load rules %s: %v", rulesFile, err)
	}
	if err := selftestHist.load(); err != nil {
		log.Printf("load self-test history %s: %v", selftestHistFile, err)
	}
	go startDemo() // 演示站点（PII_DEMO 为空则不启用）
	go startAdmin()
	log.Printf("pii-gateway listening on %s, forwarding to %s", listenAddr, appCfg.Target())
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "ok")
	})
	mux.HandleFunc("/", handleProxy)
	if err := http.ListenAndServe(listenAddr, mux); err != nil {
		log.Fatal(err)
	}
}

// handleProxy：客户端 -> 网关(脱敏) -> new-api -> 上游，响应反向还原。
func handleProxy(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	m := newMapping()
	status := 500

	defer func() {
		logs.add(LogEntry{
			Time:          start.Format("15:04:05"),
			ClientIP:      clientIP(r),
			Method:        r.Method,
			Path:          r.URL.Path,
			Status:        status,
			DurationMS:    time.Since(start).Milliseconds(),
			MaskedCount:   m.MaskedCount(),
			RestoredCount: m.Restored,
			Residual:      m.Residual,
		})
	}()

	// 1. 读请求体并脱敏（脱敏前先注入提醒模型保留占位符的 system 说明）
	rawBody, err := io.ReadAll(r.Body)
	if err != nil {
		status = http.StatusBadRequest
		http.Error(w, "read body: "+err.Error(), status)
		return
	}
	masked := mask(injectSystemHint(rawBody), m)

	// 2. 重建请求转发到 new-api
	proxyReq, err := http.NewRequest(r.Method, appCfg.Target()+r.URL.String(), bytes.NewReader(masked))
	if err != nil {
		status = http.StatusBadGateway
		http.Error(w, "build request: "+err.Error(), status)
		return
	}
	copyHeaders(proxyReq.Header, r.Header)

	client := &http.Client{}
	resp, err := client.Do(proxyReq)
	if err != nil {
		status = http.StatusBadGateway
		http.Error(w, "upstream error: "+err.Error(), status)
		return
	}
	defer resp.Body.Close()

	// 3. 还原响应头
	copyHeaders(w.Header(), resp.Header)

	if isStream(resp) {
		status = restoreStream(w, r, resp, m)
		return
	}
	status = restoreBody(w, resp, m)
}

func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if i := strings.Index(xff, ","); i > 0 {
			return strings.TrimSpace(xff[:i])
		}
		return strings.TrimSpace(xff)
	}
	host := r.RemoteAddr
	if i := strings.LastIndex(host, ":"); i > 0 {
		return host[:i]
	}
	return host
}

// restoreBody：非流式，读完整响应体还原后写回。返回 HTTP 状态码。
func restoreBody(w http.ResponseWriter, resp *http.Response, m *mapping) int {
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("read upstream body: %v", err)
	}
	data = restore(data, m)
	if strings.Contains(string(data), "<<PII:") {
		m.Residual = true
	}
	w.WriteHeader(resp.StatusCode)
	if _, err := w.Write(data); err != nil {
		log.Printf("write response: %v", err)
	}
	return resp.StatusCode
}

// restoreStream：SSE 流式，逐行还原 data: 行后写回并 flush。返回 HTTP 状态码。
// 占位符可能被模型拆到相邻 chunk，用 carry 把未闭合前缀留给下一行合并后再还原。
func restoreStream(w http.ResponseWriter, r *http.Request, resp *http.Response, m *mapping) int {
	flusher, ok := w.(http.Flusher)
	if !ok {
		// 不支持 flush 时退化为整体读取
		return restoreBody(w, resp, m)
	}

	w.WriteHeader(resp.StatusCode)
	flusher.Flush()

	var carry string // 上一个 data 行 content 值里遗留的未闭合占位符前缀
	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 64<<10), 128<<20)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "data:") {
			line, carry = restoreDataLine(line, m, carry)
		}
		if strings.Contains(line, "<<PII:") {
			m.Residual = true
		}
		if _, err := fmt.Fprintln(w, line); err != nil {
			log.Printf("stream write: %v", err)
			return resp.StatusCode
		}
		flusher.Flush()
	}
	// 流结束时若仍有残留前缀，透传给客户端（内容不丢）并记录
	if carry != "" {
		log.Printf("stream ended with dangling placeholder prefix: %s", carry)
		if _, err := fmt.Fprintln(w, carry); err != nil {
			log.Printf("stream write carry: %v", err)
		}
	}
	if err := scanner.Err(); err != nil {
		log.Printf("stream scan: %v", err)
	}
	return resp.StatusCode
}

// restoreDataLine 还原一个 data 行。模型按 token 流式输出，占位符可能被拆到
// 相邻两个 data 行的 content 字段里，所以按 content 值做跨行拼接还原。
// 返回 (还原后的 data 行, 本行 content 遗留的未闭合前缀)。
func restoreDataLine(line string, m *mapping, carry string) (string, string) {
	const mark = `"content":"`
	i := strings.Index(line, mark)
	if i < 0 {
		// 非 content 行（如 [DONE]、role、usage）：原样透传，保留 carry
		return line, carry
	}
	start := i + len(mark)
	end := findClosingQuote(line, start)
	if end < 0 {
		return line, carry
	}
	value := line[start:end]
	newValue, newCarry := restoreContent(value, m, carry)
	newLine := line[:start] + newValue + line[end:]
	return newLine, newCarry
}

// restoreContent 对单个 content 值做跨行占位符拼接还原。
// 返回 (可输出的 content 值, 遗留的未闭合前缀)。
func restoreContent(value string, m *mapping, carry string) (string, string) {
	combined := carry + value
	head, tail := splitDangling(combined)
	if tail != "" {
		return string(restore([]byte(head), m)), tail
	}
	return string(restore([]byte(combined), m)), ""
}

// splitDangling 把 s 拆成 (head, tail)。tail 是 s 末尾最长的一段「未闭合占位符前缀」，
// 若无则 tail 为空。注意不能用 LastIndex(s, "[")：[[PI 会取到第二个 [，截出 [PI 反而
// 匹配不上，所以遍历所有 [ 位置取最早能完整匹配前缀的（即最长 tail）。
func splitDangling(s string) (head, tail string) {
	for i := 0; i < len(s); i++ {
		if isDanglingPrefix(s[i:]) {
			return s[:i], s[i:]
		}
	}
	return s, ""
}

// findClosingQuote 从 start 开始找未转义的闭合双引号，找不到返回 -1。
func findClosingQuote(s string, start int) int {
	for j := start; j < len(s); j++ {
		if s[j] == '\\' {
			j++ // 跳过被转义的字符
			continue
		}
		if s[j] == '"' {
			return j
		}
	}
	return -1
}

func isStream(resp *http.Response) bool {
	ct := resp.Header.Get("Content-Type")
	return strings.Contains(strings.ToLower(ct), "text/event-stream")
}

func copyHeaders(dst, src http.Header) {
	for k, vs := range src {
		if hopHeaders[k] || strings.HasPrefix(strings.ToLower(k), "proxy-") {
			continue
		}
		for _, v := range vs {
			dst.Add(k, v)
		}
	}
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// injectSystemHint 在 OpenAI 风格 chat 请求体的 messages 数组开头注入一条 system 说明，
// 提醒模型严格保留 <<PII:...>> 占位符，降低还原失败率。
// 仅当：systemHint 非空 且 body 是含 messages 数组的 JSON 时才注入；否则原样返回。
// 用 json.RawMessage 保留 messages 之外的顶层字段字节不变（避免重序列化引入精度/顺序问题）。
func injectSystemHint(body []byte) []byte {
	if !systemHintEnabled { // 开关默认关闭；关闭时即使有文字也不注入，但文字保留以便后续打开
		return body
	}
	s := strings.TrimSpace(string(systemHint))
	if s == "" {
		return body
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(body, &obj); err != nil {
		return body // 非 JSON（如非 chat 接口），不注入
	}
	rawMsgs, ok := obj["messages"]
	if !ok {
		return body
	}
	var msgs []json.RawMessage
	if err := json.Unmarshal(rawMsgs, &msgs); err != nil {
		return body
	}
	hint, _ := json.Marshal(map[string]string{"role": "system", "content": s})
	newMsgs := make([]json.RawMessage, 0, len(msgs)+1)
	newMsgs = append(newMsgs, hint)
	newMsgs = append(newMsgs, msgs...)
	out, err := json.Marshal(newMsgs)
	if err != nil {
		return body
	}
	obj["messages"] = out
	final, err := json.Marshal(obj)
	if err != nil {
		return body
	}
	return final
}
