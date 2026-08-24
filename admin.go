package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// 环形日志存储
// ---------------------------------------------------------------------------

type LogEntry struct {
	ID            int64  `json:"id"`
	Time          string `json:"time"`
	ClientIP      string `json:"client_ip"`
	Method        string `json:"method"`
	Path          string `json:"path"`
	Status        int    `json:"status"`
	DurationMS    int64  `json:"duration_ms"`
	MaskedCount   int    `json:"masked_count"`
	RestoredCount int    `json:"restored_count"`
	Residual      bool   `json:"residual"` // 响应是否有未还原的占位符残留
	Error         string `json:"error,omitempty"`
}

type logStore struct {
	mu  sync.Mutex
	buf []LogEntry
	cap int
	seq int64
}

func newLogStore(cap int) *logStore {
	return &logStore{buf: make([]LogEntry, 0, cap), cap: cap}
}

func (l *logStore) add(e LogEntry) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.seq++
	e.ID = l.seq
	if len(l.buf) == l.cap {
		copy(l.buf, l.buf[1:])
		l.buf = l.buf[:l.cap-1]
	}
	l.buf = append(l.buf, e)
}

// list 返回全部日志，最新在前。
func (l *logStore) list() []LogEntry {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]LogEntry, len(l.buf))
	copy(out, l.buf)
	sort.Slice(out, func(i, j int) bool { return out[i].ID > out[j].ID })
	return out
}

func (l *logStore) count() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.buf)
}

var logs = newLogStore(2000)

// ---------------------------------------------------------------------------
// 管理服务
// ---------------------------------------------------------------------------

var (
	adminAddr = envOr("PII_ADMIN", ":9090")
)

// startAdmin 启动管理服务（独立端口，不干扰转发）。
func startAdmin() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", serveAdminPage)
	mux.HandleFunc("/api/health", adminHealth)
	mux.HandleFunc("/api/logs", adminLogs)
	mux.HandleFunc("/api/rules", adminRules)
	mux.HandleFunc("/api/rules/update", adminRuleUpdate)
	mux.HandleFunc("/api/rules/remove", adminRuleRemove)
	mux.HandleFunc("/api/config", adminConfig)
	mux.HandleFunc("/api/names", adminNames)
	mux.HandleFunc("/api/names/remove", adminNameRemove)
	mux.HandleFunc("/api/mappings", adminMappings)
	mux.HandleFunc("/api/mappings/ignore", adminMappingIgnore)
	mux.HandleFunc("/api/mappings/clear", adminMappingsClear)
	mux.HandleFunc("/api/self-test", adminSelfTest)
	log.Printf("pii-gateway admin panel on %s", adminAddr)
	if err := http.ListenAndServe(adminAddr, mux); err != nil {
		log.Fatalf("admin server: %v", err)
	}
}

func adminHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]any{
		"status":       "ok",
		"listen":       listenAddr,
		"target":       appCfg.Target(),
		"admin":        adminAddr,
		"log_entries":  logs.count(),
		"mapping_size": globalStore.size(),
		"now":          time.Now().Format(time.RFC3339),
	})
}

func adminLogs(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, logs.list())
}

// adminConfig 读取/设置运行配置。
func adminConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		c := appCfg.Get()
		writeJSON(w, map[string]any{
			"forward_target":     c.ForwardTarget,
			"listen_addr":        c.ListenAddr,
			"admin_addr":         c.AdminAddr,
			"store_file":         c.StoreFile,
			"rules_file":         c.RulesFile,
			"placeholder_prefix": c.PlaceholderPrefix,
			"placeholder_sep":    c.PlaceholderSep,
			"placeholder_suffix":  c.PlaceholderSuffix,
			"system_hint":         c.SystemHint,
			"system_hint_enabled": c.SystemHintEnabled,
		})
	case http.MethodPost:
		adminConfigSet(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// adminConfigSet 设置转发目标（热生效）；端口/文件类改动保存但需重启。
func adminConfigSet(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ForwardTarget     string `json:"forward_target"`
		ListenAddr        string `json:"listen_addr"`
		AdminAddr         string `json:"admin_addr"`
		PlaceholderPrefix string `json:"placeholder_prefix"`
		PlaceholderSep    string `json:"placeholder_sep"`
		PlaceholderSuffix string `json:"placeholder_suffix"`
		SystemHint        string `json:"system_hint"`
		SystemHintEnabled string `json:"system_hint_enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad json: "+err.Error(), http.StatusBadRequest)
		return
	}
	c := appCfg.Get()
	restart := false
	if t := strings.TrimSpace(req.ForwardTarget); t != "" {
		c.ForwardTarget = t
	}
	if l := strings.TrimSpace(req.ListenAddr); l != "" && l != c.ListenAddr {
		c.ListenAddr = l
		restart = true
	}
	if a := strings.TrimSpace(req.AdminAddr); a != "" && a != c.AdminAddr {
		c.AdminAddr = a
		restart = true
	}
	if p := strings.TrimSpace(req.PlaceholderPrefix); p != "" && p != c.PlaceholderPrefix {
		c.PlaceholderPrefix = p
		restart = true
	}
	if req.PlaceholderSep != "" && req.PlaceholderSep != c.PlaceholderSep {
		c.PlaceholderSep = req.PlaceholderSep
		restart = true
	}
	if req.PlaceholderSuffix != "" && req.PlaceholderSuffix != c.PlaceholderSuffix {
		c.PlaceholderSuffix = req.PlaceholderSuffix
		restart = true
	}
	if req.SystemHint != "" && req.SystemHint != c.SystemHint {
		c.SystemHint = req.SystemHint
	}
	if req.SystemHintEnabled != "" && req.SystemHintEnabled != c.SystemHintEnabled {
		c.SystemHintEnabled = req.SystemHintEnabled
	}
	// 提示说明与开关随配置热生效，无需重启
	if err := appCfg.Save(c); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]any{"ok": true, "restart_required": restart})
}

func adminRules(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		rules := globalRules.all()
		out := make([]map[string]string, 0, len(rules))
		for _, rl := range rules {
			out = append(out, map[string]string{"name": rl.Name, "type": rl.Type, "pattern": rl.Pattern, "sample": rl.Sample})
		}
		writeJSON(w, map[string]any{"rules": out})
	case http.MethodPost:
		adminRuleAdd(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// adminRuleUpdate 更新已有正则规则（名称不变，改正则/示例）。
func adminRuleUpdate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Name    string `json:"name"`    // 当前规则名（定位用）
		NewName string `json:"new_name"` // 新规则名（可为空 = 不变）
		Type    string `json:"type"`    // 占位符类型标签，可为空 = 不变
		Pattern string `json:"pattern"`
		Sample  string `json:"sample"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad json: "+err.Error(), http.StatusBadRequest)
		return
	}
	name := strings.TrimSpace(req.Name)
	pattern := strings.TrimSpace(req.Pattern)
	if name == "" || pattern == "" {
		http.Error(w, "name and pattern are required", http.StatusBadRequest)
		return
	}
	newName := strings.TrimSpace(req.NewName)
	if err := globalRules.update(name, newName, pattern, req.Sample, req.Type); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, map[string]any{"ok": true, "name": newName})
}

// adminRuleAdd 手动添加一条正则规则。
func adminRuleAdd(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name    string `json:"name"`
		Type    string `json:"type"` // 占位符类型标签，空则 UNKNOWN
		Pattern string `json:"pattern"`
		Sample  string `json:"sample"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad json: "+err.Error(), http.StatusBadRequest)
		return
	}
	name := strings.TrimSpace(req.Name)
	pattern := strings.TrimSpace(req.Pattern)
	if name == "" || pattern == "" {
		http.Error(w, "name and pattern are required", http.StatusBadRequest)
		return
	}
	if err := globalRules.add(name, pattern, req.Sample, req.Type); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, map[string]any{"ok": true, "name": name})
}

// adminNames 读取/添加敏感名单（姓名等，正文出现即掩码，热生效）。
func adminNames(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, map[string]any{"names": namesList})
	case http.MethodPost:
		adminNameAdd(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func adminNameAdd(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad json: "+err.Error(), http.StatusBadRequest)
		return
	}
	nm := strings.TrimSpace(req.Name)
	if nm == "" {
		http.Error(w, "name is required", http.StatusBadRequest)
		return
	}
	c := appCfg.Get()
	for _, x := range c.Names {
		if strings.TrimSpace(x) == nm {
			http.Error(w, "已在名单中", http.StatusBadRequest)
			return
		}
	}
	c.Names = append(c.Names, nm)
	if err := appCfg.Save(c); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]any{"ok": true, "name": nm})
}

func adminNameRemove(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad json: "+err.Error(), http.StatusBadRequest)
		return
	}
	nm := strings.TrimSpace(req.Name)
	c := appCfg.Get()
	out := c.Names[:0]
	found := false
	for _, x := range c.Names {
		if strings.TrimSpace(x) == nm {
			found = true
			continue
		}
		out = append(out, x)
	}
	if !found {
		http.Error(w, "不在名单中", http.StatusBadRequest)
		return
	}
	c.Names = out
	if err := appCfg.Save(c); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]any{"ok": true})
}

func adminRuleRemove(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad json: "+err.Error(), http.StatusBadRequest)
		return
	}
	if err := globalRules.remove(req.Name); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, map[string]any{"ok": true})
}

func adminMappings(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		entries := globalStore.list()
		encEntries := make([]map[string]any, 0, len(entries))
		for _, e := range entries {
			er, err := mapEncrypt(e.Real)
			if err != nil {
				er = e.Real // 加密失败回退明文（理论上不会发生）
			}
			encEntries = append(encEntries, map[string]any{
				"placeholder": e.Placeholder,
				"real":        er,
				"ignored":     globalStore.isIgnored(e.Real),
			})
		}
		writeJSON(w, map[string]any{
			"size":    globalStore.size(),
			"entries": encEntries,
		})
	case http.MethodPost:
		adminMappingsAdd(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// adminMappingsAdd 手动添加一条映射：传真实值，自动分配占位符并落盘。
func adminMappingsAdd(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Real string `json:"real"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad json: "+err.Error(), http.StatusBadRequest)
		return
	}
	// req.Real 由浏览器加密后发送，这里先解密为明文再处理（脱敏引擎需要明文）。
	plain := strings.TrimSpace(req.Real)
	if dec, err := mapDecrypt(plain); err == nil && dec != "" {
		plain = strings.TrimSpace(dec)
	}
	if plain == "" {
		http.Error(w, "real is required", http.StatusBadRequest)
		return
	}
	enc, _ := mapEncrypt(plain)
	// 已存在则直接返回现有占位符
	if ph, ok := globalStore.lookup(plain); ok {
		writeJSON(w, map[string]any{"placeholder": ph, "real": enc, "new": false})
		return
	}
	n := pidCounter.Add(1)
	ph := phFor(TypeUnknown, n)
	globalStore.remember(plain, ph)
	if err := globalStore.saveFile(piiStoreFile); err != nil {
		log.Printf("save pii store: %v", err)
	}
	writeJSON(w, map[string]any{"placeholder": ph, "real": enc, "new": true})
}

// adminMappingIgnore 按占位符切换某条映射的忽略状态（忽略后不再脱敏该真实值，可恢复）。
func adminMappingIgnore(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Placeholder string `json:"placeholder"`
		Ignored     bool   `json:"ignored"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad json: "+err.Error(), http.StatusBadRequest)
		return
	}
	if err := globalStore.setIgnored(req.Placeholder, req.Ignored); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, map[string]any{"ok": true})
}

func adminMappingsClear(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	globalStore.clear()
	writeJSON(w, map[string]any{"ok": true, "size": 0})
}

// adminSelfTest 离线演示一次「脱敏 -> 还原」往返，不真正调用模型。
func adminSelfTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Text string `json:"text"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad json: "+err.Error(), http.StatusBadRequest)
		return
	}
	m := newMapping()
	masked := mask([]byte(req.Text), m)
	restored := restore(masked, m)
	writeJSON(w, map[string]any{
		"masked":   string(masked),
		"restored": string(restored),
		"count":    m.MaskedCount(),
	})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(v)
}

// ---------------------------------------------------------------------------
// 映射表真实值传输加密（AES-256-GCM，浏览器 <-> 后端）
// ---------------------------------------------------------------------------
//
// 目的：映射表里真实值是敏感 PII，避免在浏览器<->后端的请求/响应里以明文传输
// （被抓包、代理、日志记录看到）。浏览器用同一密钥加密发送、解密显示。
//
// 注意：这是“混淆级”加密——密钥硬编码在前端 JS 与后端，攻击者可读前端源码拿到
// 密钥，因此只能防“无心”的抓包/明文日志，不能防定向攻击。
// 脱敏/还原引擎需要明文真实值做子串匹配，所以后端内部存储与 store.json 落盘
// 仍为明文，加密只作用于 API 传输边界。

var mapSecretKey = []byte("pii-gateway-map-secret-2026")

func mapAesGCM() (cipher.AEAD, error) {
	sum := sha256.Sum256(mapSecretKey) // 32 字节 -> AES-256 密钥，与前端 SHA-256 派生一致
	block, err := aes.NewCipher(sum[:])
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// mapEncrypt 加密明文真实值，返回 base64(iv || ciphertext)。
func mapEncrypt(plain string) (string, error) {
	gcm, err := mapAesGCM()
	if err != nil {
		return "", err
	}
	iv := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(iv); err != nil {
		return "", err
	}
	ct := gcm.Seal(nil, iv, []byte(plain), nil)
	out := make([]byte, 0, len(iv)+len(ct))
	out = append(out, iv...)
	out = append(out, ct...)
	return base64.StdEncoding.EncodeToString(out), nil
}

// mapDecrypt 解密 base64(iv || ciphertext) 得到明文。
func mapDecrypt(enc string) (string, error) {
	gcm, err := mapAesGCM()
	if err != nil {
		return "", err
	}
	raw, err := base64.StdEncoding.DecodeString(enc)
	if err != nil {
		return "", err
	}
	if len(raw) < gcm.NonceSize() {
		return "", fmt.Errorf("ciphertext too short")
	}
	iv, ct := raw[:gcm.NonceSize()], raw[gcm.NonceSize():]
	pt, err := gcm.Open(nil, iv, ct, nil)
	if err != nil {
		return "", err
	}
	return string(pt), nil
}

// ---------------------------------------------------------------------------
// 管理页面（内嵌 HTML）
// ---------------------------------------------------------------------------

const adminPageHTML = `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>PII 脱敏网关</title>
<style>
:root{
  --bg:#f7f8fa;--surface:#ffffff;--card:#ffffff;--line:#e4e7ec;--line-strong:#d0d5dd;
  --fg:#101828;--fg-secondary:#344054;--muted:#667085;
  --ok:#027a48;--ok-bg:#ecfdf3;--warn:#b54708;--warn-bg:#fffaeb;--err:#b42318;--err-bg:#fef3f2;
  --accent:#4f46e5;--accent-hover:#4338ca;--accent-bg:#eef4ff;
  --shadow:0 1px 3px rgba(16,24,40,.08),0 1px 2px rgba(16,24,40,.04);
  --shadow-md:0 4px 8px -2px rgba(16,24,40,.08),0 2px 4px -2px rgba(16,24,40,.04);
  --overlay:rgba(15,17,23,.45);
  --radius:10px;--radius-sm:8px;
}
body.theme-dark{
  --bg:#0f1117;--surface:#131620;--card:#181b25;--line:#262a38;--line-strong:#2f3447;
  --fg:#f2f4f7;--fg-secondary:#e4e7ec;--muted:#8b90a0;
  --ok:#34d399;--ok-bg:rgba(52,211,153,.12);--warn:#fbbf24;--warn-bg:rgba(251,191,36,.12);--err:#f87171;--err-bg:rgba(248,113,113,.12);
  --accent:#818cf8;--accent-hover:#a5b4fc;--accent-bg:rgba(99,102,241,.15);
  --shadow:0 1px 3px rgba(0,0,0,.35);--shadow-md:0 4px 8px rgba(0,0,0,.4);
  --overlay:rgba(0,0,0,.65);
}
*{box-sizing:border-box}html{scroll-behavior:smooth}
body{margin:0;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,'Helvetica Neue',Arial,'Noto Sans',sans-serif,'Apple Color Emoji','Segoe UI Emoji';background:var(--bg);color:var(--fg);font-size:14px;line-height:1.5}
.wrap{max-width:1120px;margin:0 auto;padding:28px 24px}
h1{font-size:22px;font-weight:600;margin:0 0 4px;letter-spacing:-.2px}
.sub{color:var(--muted);font-size:13px;margin-bottom:22px}
.top{display:flex;justify-content:space-between;align-items:flex-start;gap:16px}
.theme-btn{background:var(--card);color:var(--fg-secondary);border:1px solid var(--line);border-radius:var(--radius-sm);padding:7px 14px;cursor:pointer;font-size:13px;font-weight:500;box-shadow:var(--shadow);transition:all .15s ease}
.theme-btn:hover{border-color:var(--line-strong);background:var(--surface);transform:translateY(-1px)}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:14px;margin-bottom:24px}
.card{background:var(--card);border:1px solid var(--line);border-radius:var(--radius);padding:16px;box-shadow:var(--shadow);transition:transform .15s ease,box-shadow .15s ease}
.card:hover{transform:translateY(-1px);box-shadow:var(--shadow-md)}
.card .k{color:var(--muted);font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.5px;margin-bottom:8px}
.card .v{font-size:20px;font-weight:600;color:var(--fg);line-height:1.3}
.pill{display:inline-flex;align-items:center;gap:5px;padding:3px 10px;border-radius:999px;font-size:12px;font-weight:500}
.pill.ok{background:var(--ok-bg);color:var(--ok);border:1px solid color-mix(in srgb,var(--ok) 22%,transparent)}
.pill.warn{background:var(--warn-bg);color:var(--warn);border:1px solid color-mix(in srgb,var(--warn) 22%,transparent)}
.pill.bad{background:var(--err-bg);color:var(--err);border:1px solid color-mix(in srgb,var(--err) 22%,transparent)}
.pill.line{background:var(--accent-bg);color:var(--accent);border:1px solid color-mix(in srgb,var(--accent) 22%,transparent)}
h2{font-size:15px;font-weight:600;margin:0 0 14px;color:var(--fg)}
.panel{background:var(--card);border:1px solid var(--line);border-radius:var(--radius);padding:20px;margin-bottom:22px;box-shadow:var(--shadow)}
table{width:100%;border-collapse:separate;border-spacing:0;font-size:13px}
th,td{text-align:left;padding:10px 12px;border-bottom:1px solid var(--line);vertical-align:top;white-space:nowrap}
th{color:var(--muted);font-weight:600;font-size:11px;text-transform:uppercase;letter-spacing:.5px;background:var(--bg)}
thead tr:first-child th{border-top:1px solid var(--line)}
thead th:first-child{border-radius:var(--radius-sm) 0 0 0}
thead th:last-child{border-radius:0 var(--radius-sm) 0 0}
tr:hover td{background:var(--bg)}
.err{color:var(--err)}.okc{color:var(--ok)}.warn{color:var(--warn)}
textarea{width:100%;min-height:84px;background:var(--bg);color:var(--fg);border:1px solid var(--line);border-radius:var(--radius-sm);padding:10px 12px;font-family:inherit;font-size:13px;line-height:1.5;resize:vertical;transition:border-color .15s,box-shadow .15s}
textarea:focus,.inp:focus{outline:none;border-color:var(--accent);box-shadow:0 0 0 3px var(--accent-bg)}
.inp{flex:1;background:var(--bg);color:var(--fg);border:1px solid var(--line);border-radius:var(--radius-sm);padding:8px 12px;font-family:inherit;font-size:13px;transition:border-color .15s,box-shadow .15s}
button{background:var(--accent);border:none;color:#fff;padding:8px 16px;border-radius:var(--radius-sm);cursor:pointer;font-size:13px;font-weight:500;transition:background .15s,transform .1s,box-shadow .15s}
button:hover{background:var(--accent-hover);box-shadow:var(--shadow-md)}
button:active{transform:translateY(1px)}
button.secondary{background:var(--bg);color:var(--fg-secondary);border:1px solid var(--line)}
button.secondary:hover{background:var(--surface);border-color:var(--line-strong)}
button.danger{background:var(--err-bg);color:var(--err);border:1px solid color-mix(in srgb,var(--err) 22%,transparent)}
button.danger:hover{background:var(--err-bg);filter:brightness(.97)}
.pair{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-top:14px}
.pair .lbl{color:var(--muted);font-size:12px;font-weight:500;margin-bottom:6px}
.out{background:var(--bg);border:1px solid var(--line);border-radius:var(--radius-sm);padding:12px;min-height:44px;word-break:break-all;white-space:pre-wrap;font-size:13px;line-height:1.5;color:var(--fg-secondary)}
.muted{color:var(--muted)}.mb{margin-bottom:8px}
a{color:var(--accent);text-decoration:none}
a:hover{text-decoration:underline}
.empty-row td{color:var(--muted);text-align:center;padding:18px 12px}
.tabbar{position:sticky;top:0;z-index:50;display:flex;gap:6px;flex-wrap:wrap;background:var(--bg);padding:10px 0;border-bottom:1px solid var(--line);margin-bottom:18px}
.tab-btn{background:var(--card);color:var(--fg-secondary);border:1px solid var(--line);border-radius:var(--radius-sm);padding:7px 14px;cursor:pointer;font-size:13px;font-weight:500;transition:all .15s}
.tab-btn:hover{border-color:var(--line-strong);background:var(--surface)}
.tab-btn.active{background:var(--accent);color:#fff;border-color:var(--accent);box-shadow:var(--shadow-md)}
@media (max-width:640px){
  .wrap{padding:18px 16px}
  .pair{grid-template-columns:1fr}
  .top{flex-direction:column;gap:12px}
  h1{font-size:20px}
}
</style>
</head>
<body>
<div class="wrap">
  <div class="top">
    <div>
      <h1>🔐 PII 脱敏网关</h1>
      <div class="sub">在 LLM 网关前自动脱敏手机号/身份证，响应自动还原 · 管理端口 <span id="adminAddr">—</span></div>
    </div>
    <button class="theme-btn" id="themeBtn" onclick="toggleTheme()">☀️ 浅色</button>
  </div>

  <div class="tabbar">
    <button class="tab-btn active" data-tabbtn="overview" onclick="switchTab('overview')">📊 概览</button>
    <button class="tab-btn" data-tabbtn="settings" onclick="switchTab('settings')">⚙️ 设置</button>
    <button class="tab-btn" data-tabbtn="selftest" onclick="switchTab('selftest')">🧪 自测</button>
    <button class="tab-btn" data-tabbtn="rules" onclick="switchTab('rules')">🧩 规则</button>
    <button class="tab-btn" data-tabbtn="names" onclick="switchTab('names')">🛡️ 名单</button>
    <button class="tab-btn" data-tabbtn="mappings" onclick="switchTab('mappings')">🗺️ 映射</button>
  </div>

  <div class="grid" id="stats" data-tab="overview"></div>

  <div class="panel" data-tab="settings">
    <h2>⚙️ 设置 <span class="muted">(转发目标热生效；端口改动需重启)</span></h2>
    <div style="display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-bottom:10px">
      <span class="muted" style="min-width:70px">转发目标</span>
      <input id="cfgTarget" class="inp" style="flex:1;min-width:240px" placeholder="http://172.17.0.1:3029">
      <button onclick="saveConfig()">💾 保存</button>
    </div>
    <div style="display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-bottom:6px">
      <span class="muted" style="min-width:70px">代理端口</span>
      <input id="cfgListen" class="inp" style="width:120px">
      <span class="muted" style="margin-left:12px">管理端口</span>
      <input id="cfgAdmin" class="inp" style="width:120px">
    </div>
    <div style="display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-bottom:6px">
      <span class="muted" style="min-width:70px">占位符格式</span>
      <input id="cfgPhPrefix" class="inp" style="width:84px" placeholder="前缀">
      <input id="cfgPhSep" class="inp" style="width:56px" placeholder="分隔">
      <input id="cfgPhSuffix" class="inp" style="width:84px" placeholder="后缀">
      <span class="muted">例：<code>&lt;&lt;PII:PHONE:1&gt;&gt;</code>（改后需重启并清空旧映射）</span>
    </div>
    <div style="margin-top:12px">
      <div class="lbl" style="color:var(--muted);font-size:12px;font-weight:500;margin-bottom:6px">注入给上游模型的说明 <span class="muted">(提醒保留 &lt;&lt;PII:...&gt;&gt; 占位符)</span></div>
      <div style="display:flex;gap:8px;align-items:center;margin-bottom:8px">
        <input type="checkbox" id="cfgSystemHintEnabled" style="width:16px;height:16px;accent-color:var(--accent)">
        <label for="cfgSystemHintEnabled" class="muted">启用注入（默认关闭）</label>
      </div>
      <textarea id="cfgSystemHint" rows="3" placeholder="请严格原样保留所有形如 &lt;&lt;PII:...&gt;&gt; 的占位符…"></textarea>
    </div>
    <div class="muted">映射文件 <span id="cfgStore"></span> · 规则文件 <span id="cfgRules"></span></div>
    <div id="cfgMsg" style="margin-top:8px"></div>
  </div>

  <div class="panel" data-tab="selftest">
    <h2>🧪 脱敏自测（不调模型，直接演示）</h2>
    <textarea id="selftest" placeholder="输入包含手机号/身份证的文本，例如：我的电话是13812345678，身份证110101199003071234"></textarea>
    <div style="margin-top:10px"><button onclick="runSelfTest()">运行自测</button></div>
    <div class="pair">
      <div><div class="lbl">脱敏后（发往上游）</div><div class="out" id="maskedOut">—</div></div>
      <div><div class="lbl">还原后（返回客户端）</div><div class="out" id="restoredOut">—</div></div>
    </div>
  </div>

  <div class="panel" data-tab="rules">
    <h2>🧩 正则规则 <span class="muted">(脱敏匹配规则，可增删改，落盘持久)</span></h2>
    <div style="display:flex;gap:8px;margin-bottom:12px;flex-wrap:wrap">
      <input id="ruleName" class="inp" style="flex:1;min-width:140px" placeholder="规则名，如：银行卡号">
      <input id="ruleType" class="inp" style="width:110px" placeholder="类型，如 PHONE" title="占位符类型标签，如 PHONE/IDCARD/EMAIL，留空则为 UNKNOWN">
      <input id="rulePattern" class="inp" style="flex:2;min-width:220px" placeholder="正则，如：\\d{16,19}" onkeydown="if(event.key==='Enter')addRule()">
      <button onclick="addRule()">➕ 添加规则</button>
    </div>
    <div style="overflow-x:auto"><table>
      <thead><tr><th>规则名</th><th>类型</th><th>正则</th><th>示例</th><th style="width:120px"></th></tr></thead>
      <tbody id="ruleBody"></tbody>
    </table></div>
    <div class="muted" id="ruleEmpty" style="margin-top:10px">暂无规则</div>
  </div>

  <div id="editModal" style="display:none;position:fixed;inset:0;background:var(--overlay);z-index:100;align-items:center;justify-content:center;padding:20px">
    <div style="background:var(--card);border:1px solid var(--line);border-radius:var(--radius);width:100%;max-width:560px;box-shadow:var(--shadow-md);padding:22px">
      <h2 style="margin-bottom:16px">✏️ 编辑规则</h2>
      <input type="hidden" id="editOrigName">
      <div class="mb"><div class="lbl">规则名</div><input id="editName" class="inp" placeholder="规则名，如：银行卡号"></div>
      <div class="mb"><div class="lbl">类型 <span class="muted">(占位符标签，留空保持原值)</span></div><input id="editType" class="inp" placeholder="如 PHONE/IDCARD/EMAIL"></div>
      <div class="mb"><div class="lbl">正则</div><textarea id="editPattern" rows="4" placeholder="输入正则表达式"></textarea></div>
      <div class="mb"><div class="lbl">示例</div><input id="editSample" class="inp" placeholder="可选：填写一个匹配示例"></div>
      <div style="display:flex;gap:10px;justify-content:flex-end;margin-top:18px">
        <button class="secondary" onclick="closeEditModal()">取消</button>
        <button onclick="saveRuleEdit()">保存修改</button>
      </div>
    </div>
  </div>

  <div class="panel" data-tab="names">
    <h2>🛡️ 敏感名单 <span class="muted">(姓名等固定词，正文出现即掩码为 &lt;&lt;PII:NAME:n&gt;&gt;，热生效)</span></h2>
    <div style="display:flex;gap:8px;margin-bottom:12px">
      <input id="newName" style="flex:1" class="inp" placeholder="输入姓名/敏感词，如：张三" onkeydown="if(event.key==='Enter')addName()">
      <button onclick="addName()">➕ 添加</button>
    </div>
    <div style="display:flex;flex-wrap:wrap;gap:8px" id="nameBody"></div>
    <div class="muted" id="nameEmpty" style="margin-top:10px">暂无名单</div>
  </div>

  <div class="panel" data-tab="mappings">
    <h2>🗺️ 映射表 <span class="muted">(<span id="mapCount">0</span> 条 · 同一内容跨请求复用同一占位符)</span>
      <button class="danger" style="float:right" onclick="clearMappings()">🗑️ 清除全部</button>
    </h2>
    <div style="display:flex;gap:8px;margin-bottom:12px">
      <input id="newReal" style="flex:1" class="inp" placeholder="手动添加真实值，如 1111 —— 自动分配占位符" onkeydown="if(event.key==='Enter')addMapping()">
      <button onclick="addMapping()">➕ 添加</button>
    </div>
    <div style="display:flex;gap:8px;margin-bottom:12px">
      <input id="mapFilter" class="inp" style="flex:1" placeholder="🔍 按占位符过滤，如 PHONE 或 <<PII:PHONE:1>>" oninput="loadMappings()">
    </div>
    <div style="overflow-x:auto"><table>
      <thead><tr><th>占位符</th><th>真实值</th><th style="width:90px">忽略</th></tr></thead>
      <tbody id="mapBody"></tbody>
    </table></div>
    <div class="muted" id="mapEmpty" style="margin-top:10px">暂无映射</div>
  </div>

  <div class="panel" data-tab="overview">
    <h2>🧾 实时转发日志 <span class="muted">(<span id="logCount">0</span> 条，自动刷新)</span></h2>
    <div style="overflow-x:auto"><table>
      <thead><tr><th>时间</th><th>IP</th><th>方法</th><th>路径</th><th>状态</th><th>耗时</th><th>脱敏</th><th>还原</th><th>残留</th></tr></thead>
      <tbody id="logBody"></tbody>
    </table></div>
  </div>
</div>

<script>
const $$ = id => document.getElementById(id);
async function j(url,opt){const r=await fetch(url,opt);return r.json()}

async function refresh(){
  try{
    const h = await j('/api/health');
    $$('adminAddr').textContent = h.admin;
    $$('stats').innerHTML = [
      ['状态', '<span class="pill ok">● 运行中</span>'],
      ['监听端口', h.listen],
      ['转发目标', '<span class="pill line">'+h.target+'</span>'],
      ['日志条数', h.log_entries],
      ['映射条目', h.mapping_size],
      ['当前时间', h.now]
    ].map(([k,v])=>'<div class="card"><div class="k">'+k+'</div><div class="v">'+v+'</div></div>').join('');
  }catch(e){ $$('stats').innerHTML='<div class="card"><div class="k">管理端</div><div class="v err">连接失败</div></div>'; }

  try{
    const logs = await j('/api/logs');
    $$('logCount').textContent = logs.length;
    $$('logBody').innerHTML = logs.map(l=>{
      const st = l.status>=500?'bad':(l.status>=400?'warn':'ok');
      const cls = l.status>=400?'err':'okc';
      return '<tr><td>'+l.time+'</td><td>'+l.client_ip+'</td><td>'+l.method+'</td><td>'+l.path+'</td>'+
        '<td class="'+cls+'">'+l.status+'</td><td>'+l.duration_ms+' ms</td>'+
        '<td>'+(l.masked_count||0)+'</td><td>'+(l.restored_count||0)+'</td>'+
        '<td>'+(l.residual?'<span class="pill bad">残留</span>':'—')+'</td></tr>';
    }).join('') || '<tr class="empty-row"><td colspan="9">暂无转发日志，等请求经过网关后自动出现。</td></tr>';
  }catch(e){}
}

async function runSelfTest(){
  const text = $$('selftest').value;
  if(!text){alert('请先输入文本');return}
  try{
    const r = await j('/api/self-test',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({text})});
    $$('maskedOut').textContent = r.masked;
    $$('restoredOut').textContent = r.restored + (r.count? '\n（共脱敏 '+r.count+' 处）':'');
  }catch(e){ $$('maskedOut').textContent='错误: '+e }
}

function truncate(s, n){
  if(!s) return '';
  return s.length > n ? s.slice(0,n)+'…' : s;
}
async function loadRules(){
  try{
    const d = await j('/api/rules');
    $$('ruleBody').innerHTML = d.rules.map(r=>{
      const short = truncate(r.pattern, 24);
      const smp = truncate(r.sample, 18) || '—';
      return '<tr><td>'+truncate(r.name, 14)+'</td>'+
        '<td><code>'+escapeHtml(r.type||'UNKNOWN')+'</code></td>'+
        '<td><code title="'+escapeHtml(r.pattern)+'">'+escapeHtml(short)+'</code></td>'+
        '<td title="'+escapeHtml(r.sample||'')+'">'+escapeHtml(smp)+'</td>'+
        '<td><button class="secondary" style="padding:3px 12px;margin-right:6px" onclick="openEditModal('+escapeHtml(JSON.stringify(r))+')">编辑</button>'+
        '<button class="danger" style="padding:3px 12px" onclick="removeRule('+escapeHtml(JSON.stringify(r.name))+')">删除</button></td></tr>';
    }).join('');
    $$('ruleEmpty').style.display = d.rules.length? 'none':'block';
  }catch(e){}
}
function escapeHtml(s){
  return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

$$('editModal').addEventListener('click', e=>{ if(e.target===$$('editModal')) closeEditModal(); });
document.addEventListener('keydown', e=>{ if(e.key==='Escape') closeEditModal(); });
function openEditModal(r){
  $$('editOrigName').value = r.name;
  $$('editName').value = r.name;
  $$('editType').value = r.type || '';
  $$('editPattern').value = r.pattern;
  $$('editSample').value = r.sample || '';
  $$('editModal').style.display = 'flex';
  $$('editName').focus();
}
function closeEditModal(){
  $$('editModal').style.display = 'none';
}
async function saveRuleEdit(){
  const name = $$('editOrigName').value;     // 当前名（定位用）
  const newName = $$('editName').value.trim(); // 新名（可改）
  const type = $$('editType').value.trim();  // 占位符类型标签（可改，留空保持原值）
  const pattern = $$('editPattern').value.trim();
  const sample = $$('editSample').value.trim();
  if(!newName){ alert('请填写规则名'); return; }
  if(!pattern){ alert('请填写正则'); return; }
  try{
    await j('/api/rules/update',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name,new_name:newName,type,pattern,sample})});
    closeEditModal(); loadRules();
  }catch(e){ alert('更新失败: '+e) }
}
async function addRule(){
  const name = $$('ruleName').value.trim(), pattern = $$('rulePattern').value.trim();
  const type = $$('ruleType').value.trim();
  if(!name||!pattern){ alert('请填写规则名和正则'); return; }
  try{
    await j('/api/rules',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name,type,pattern})});
    $$('ruleName').value=''; $$('ruleType').value=''; $$('rulePattern').value=''; loadRules();
  }catch(e){ alert('添加失败: '+e) }
}
async function removeRule(name){
  if(!confirm('删除规则「'+name+'」？')) return;
  try{ await j('/api/rules/remove',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name})}); loadRules(); }
  catch(e){ alert('删除失败: '+e) }
}
// ---- 敏感名单 ----
async function loadNames(){
  try{
    const d = await j('/api/names');
    $$('nameBody').innerHTML = d.names.map(n=>
      '<span style="display:inline-flex;align-items:center;gap:6px;background:var(--accent-bg);border:1px solid var(--accent);border-radius:999px;padding:4px 10px;font-size:13px">'
      +escapeHtml(n)+' <button class="danger" style="padding:0 7px;line-height:1.6" onclick="removeName('+escapeHtml(JSON.stringify(n))+')">✕</button></span>'
    ).join('') || '';
    $$('nameEmpty').style.display = d.names.length? 'none':'block';
  }catch(e){}
}
async function addName(){
  const n = $$('newName').value.trim();
  if(!n){ alert('请输入姓名/敏感词'); return; }
  try{ await j('/api/names',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name:n})}); $$('newName').value=''; loadNames(); }
  catch(e){ alert('添加失败: '+e) }
}
async function removeName(n){
  if(!confirm('从敏感名单移除「'+n+'」？')) return;
  try{ await j('/api/names/remove',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name:n})}); loadNames(); }
  catch(e){ alert('移除失败: '+e) }
}
// ---- 映射表真实值传输加密（AES-256-GCM，与后端共享密钥）----
const MAP_SECRET = 'pii-gateway-map-secret-2026';
async function mapKey(){
  const enc = new TextEncoder();
  const digest = await crypto.subtle.digest('SHA-256', enc.encode(MAP_SECRET)); // 32字节 = AES-256
  return crypto.subtle.importKey('raw', digest, {name:'AES-GCM'}, false, ['encrypt','decrypt']);
}
async function encReal(plain){
  const key = await mapKey();
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({name:'AES-GCM', iv}, key, new TextEncoder().encode(plain));
  const buf = new Uint8Array(iv.length + ct.byteLength);
  buf.set(iv, 0); buf.set(new Uint8Array(ct), iv.length);
  let bin=''; for(let i=0;i<buf.length;i++) bin += String.fromCharCode(buf[i]);
  return btoa(bin);
}
async function decReal(b64){
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for(let i=0;i<bin.length;i++) bytes[i]=bin.charCodeAt(i);
  const key = await mapKey();
  const iv = bytes.slice(0,12);
  const ct = bytes.slice(12);
  const pt = await crypto.subtle.decrypt({name:'AES-GCM', iv}, key, ct);
  return new TextDecoder().decode(pt);
}
// 解密结果缓存：占位符 -> 真实值，避免每次刷新都重新 AES 解密（解密是主要卡顿来源）。
const realCache = {};
async function cachedReal(e){
  if(!(e.placeholder in realCache)){
    try{ realCache[e.placeholder] = await decReal(e.real); }
    catch(err){ realCache[e.placeholder] = e.real; }
  }
  return realCache[e.placeholder];
}
async function loadMappings(){
  try{
    const d = await j('/api/mappings');
    const f = ($$('mapFilter').value||'').toLowerCase();
    const filtered = f? d.entries.filter(e=>e.placeholder.toLowerCase().includes(f)) : d.entries;
    const rows = await Promise.all(filtered.map(async e=>{
      const real = await cachedReal(e);
      const ig = !!e.ignored;
      // 占位符 <<PII:...>> 含 < >，必须 HTML 转义，否则被当标签吞掉只剩 <>
      return '<tr><td>'+escapeHtml(e.placeholder)+'</td><td>'+escapeHtml(real)+'</td>'+
        '<td><button class="'+(ig?'':'secondary')+'" style="padding:3px 12px" onclick="toggleIgnore('+escapeHtml(JSON.stringify(e.placeholder))+','+ig+', this)">'+(ig?'✅ 已忽略':'忽略')+'</button></td></tr>';
    }));
    $$('mapCount').textContent = d.size;
    $$('mapBody').innerHTML = rows.join('') || '<tr class="empty-row"><td colspan="3">无匹配项</td></tr>';
    $$('mapEmpty').style.display = d.size? 'none':'block';
  }catch(e){}
}
// 乐观更新：点击立即切换按钮状态，不等接口返回，失败再回滚。
async function toggleIgnore(ph, cur, btn){
  const now = !cur;
  if(btn){ btn.textContent = now? '✅ 已忽略':'忽略'; btn.className = now? '':'secondary'; }
  try{
    await j('/api/mappings/ignore',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({placeholder:ph, ignored:now})});
    loadMappings();
  }catch(e){
    if(btn){ btn.textContent = cur? '✅ 已忽略':'忽略'; btn.className = cur? '':'secondary'; }
    alert('操作失败: '+e);
  }
}
async function addMapping(){
  const real = $$('newReal').value.trim();
  if(!real){ alert('请输入要添加的真实值'); return; }
  try{
    const enc = await encReal(real); // 加密后发送，传输中不为明文
    const r = await j('/api/mappings',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({real:enc})});
    alert('已'+(r.new?'新增':'复用')+'映射：'+real+' → '+r.placeholder);
    $$('newReal').value='';
    loadMappings();
  }catch(e){ alert('添加失败: '+e) }
}
async function clearMappings(){
  if(!confirm('确定清除全部映射？清除后同一内容会重新分配新的占位符。')) return;
  try{
    await j('/api/mappings/clear',{method:'POST'});
    loadMappings(); refresh();
  }catch(e){ alert('清除失败: '+e) }
}

function switchTab(name){
  document.querySelectorAll('[data-tab]').forEach(el=>{
    el.style.display = (el.getAttribute('data-tab')===name)? '' : 'none';
  });
  document.querySelectorAll('.tab-btn').forEach(b=>{
    b.classList.toggle('active', b.getAttribute('data-tabbtn')===name);
  });
  // 按需加载当前 tab 的数据，不做后台轮询
  if(name==='overview') refresh();
  else if(name==='settings') loadConfig();
  else if(name==='rules') loadRules();
  else if(name==='names') loadNames();
  else if(name==='mappings') loadMappings();
  // selftest 无需预加载
}

function applyTheme(t){
  document.body.classList.toggle('theme-dark', t==='dark');
  localStorage.setItem('pii_theme', t);
  $$('themeBtn').textContent = t==='dark'? '🌙 深色' : '☀️ 浅色';
}
function toggleTheme(){ applyTheme(localStorage.getItem('pii_theme')==='dark'?'light':'dark'); }

async function loadConfig(){
  try{
    const c = await j('/api/config');
    $$('cfgTarget').value = c.forward_target;
    $$('cfgListen').value = c.listen_addr;
    $$('cfgAdmin').value = c.admin_addr;
    $$('cfgStore').textContent = c.store_file;
    $$('cfgRules').textContent = c.rules_file;
    $$('cfgPhPrefix').value = c.placeholder_prefix;
    $$('cfgPhSep').value = c.placeholder_sep;
    $$('cfgPhSuffix').value = c.placeholder_suffix;
    $$('cfgSystemHint').value = c.system_hint || '';
    $$('cfgSystemHintEnabled').checked = ['on','true','1','yes'].includes(String(c.system_hint_enabled||'').toLowerCase());
  }catch(e){}
}
async function saveConfig(){
  const body = {
    forward_target: $$('cfgTarget').value.trim(),
    listen_addr: $$('cfgListen').value.trim(),
    admin_addr: $$('cfgAdmin').value.trim(),
    placeholder_prefix: $$('cfgPhPrefix').value.trim(),
    placeholder_sep: $$('cfgPhSep').value,
    placeholder_suffix: $$('cfgPhSuffix').value,
    system_hint: $$('cfgSystemHint').value,
    system_hint_enabled: $$('cfgSystemHintEnabled').checked ? 'on':'off'
  };
  try{
    const r = await j('/api/config',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
    $$('cfgMsg').innerHTML = r.restart_required? '<span class="err">已保存：端口改动需重启后生效</span>' : '<span class="okc">已保存：转发目标已生效</span>';
    loadConfig(); refresh();
  }catch(e){ $$('cfgMsg').innerHTML='<span class="err">保存失败: '+e+'</span>' }
}

// 配置类数据(规则/名单/映射/设置)按需加载，不做轮询；
// 仅日志实时刷新，且只在概览 tab 激活时拉取，降低到 2s。
switchTab('overview');
setInterval(()=>{
  const active = document.querySelector('.tab-btn.active');
  if(active && active.getAttribute('data-tabbtn')==='overview') refresh();
}, 2000);
applyTheme(localStorage.getItem('pii_theme')||'light');
</script>
</body>
</html>
`

func serveAdminPage(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, adminPageHTML)
}
