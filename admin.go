package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sort"
	"strconv"
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
	mux.HandleFunc("/api/rules/remove", adminRuleRemove)
	mux.HandleFunc("/api/config", adminConfig)
	mux.HandleFunc("/api/mappings", adminMappings)
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
			"forward_target": c.ForwardTarget,
			"listen_addr":    c.ListenAddr,
			"admin_addr":     c.AdminAddr,
			"store_file":     c.StoreFile,
			"rules_file":     c.RulesFile,
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
		ForwardTarget string `json:"forward_target"`
		ListenAddr    string `json:"listen_addr"`
		AdminAddr     string `json:"admin_addr"`
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
			out = append(out, map[string]string{"name": rl.Name, "pattern": rl.Pattern, "sample": rl.Sample})
		}
		writeJSON(w, map[string]any{"rules": out})
	case http.MethodPost:
		adminRuleAdd(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// adminRuleAdd 手动添加一条正则规则。
func adminRuleAdd(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name    string `json:"name"`
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
	if err := globalRules.add(name, pattern, req.Sample); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, map[string]any{"ok": true, "name": name})
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
		writeJSON(w, map[string]any{
			"size":    globalStore.size(),
			"entries": globalStore.list(),
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
	real := strings.TrimSpace(req.Real)
	if real == "" {
		http.Error(w, "real is required", http.StatusBadRequest)
		return
	}
	// 已存在则直接返回现有占位符
	if ph, ok := globalStore.lookup(real); ok {
		writeJSON(w, map[string]any{"placeholder": ph, "real": real, "new": false})
		return
	}
	n := pidCounter.Add(1)
	ph := "[[PID_" + strconv.FormatUint(n, 10) + "]]"
	globalStore.remember(real, ph)
	if err := globalStore.saveFile(piiStoreFile); err != nil {
		log.Printf("save pii store: %v", err)
	}
	writeJSON(w, map[string]any{"placeholder": ph, "real": real, "new": true})
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
// 管理页面（内嵌 HTML）
// ---------------------------------------------------------------------------

const adminPageHTML = `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>PII 脱敏网关</title>
<style>
:root{--bg:#0f1117;--card:#181b25;--line:#262a38;--fg:#e6e8ee;--muted:#8b90a0;--ok:#34d399;--warn:#fbbf24;--err:#f87171;--accent:#6366f1}
body.theme-light{--bg:#f6f8fb;--card:#ffffff;--line:#e5e8ee;--fg:#1f2430;--muted:#68707f;--ok:#059669;--warn:#b45309;--err:#dc2626;--accent:#4f46e5}
*{box-sizing:border-box}body{margin:0;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;background:var(--bg);color:var(--fg);font-size:14px}
.wrap{max-width:1100px;margin:0 auto;padding:24px}
h1{font-size:20px;margin:0 0 4px}.sub{color:var(--muted);margin-bottom:20px}
.top{display:flex;justify-content:space-between;align-items:flex-start}
.theme-btn{background:var(--card);color:var(--fg);border:1px solid var(--line);border-radius:8px;padding:6px 12px;cursor:pointer;font-size:13px}
.theme-btn:hover{opacity:.85}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:12px;margin-bottom:20px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px}
.card .k{color:var(--muted);font-size:12px;margin-bottom:6px}.card .v{font-size:18px}
.pill{display:inline-block;padding:2px 10px;border-radius:999px;font-size:12px;margin:2px}
.pill.ok{background:rgba(52,211,153,.15);color:var(--ok);border:1px solid rgba(52,211,153,.4)}
.pill.bad{background:rgba(248,113,113,.15);color:var(--err);border:1px solid rgba(248,113,113,.4)}
.pill.line{background:rgba(99,102,241,.15);color:var(--accent);border:1px solid rgba(99,102,241,.4)}
h2{font-size:15px;margin:0 0 12px}
.panel{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px;margin-bottom:20px}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);vertical-align:top;white-space:nowrap}
th{color:var(--muted);font-weight:normal}
tr:hover td{background:rgba(255,255,255,.02)}
.err{color:var(--err)}.okc{color:var(--ok)}
textarea{width:100%;min-height:70px;background:var(--bg);color:var(--fg);border:1px solid var(--line);border-radius:8px;padding:10px;font-family:inherit;resize:vertical}
.inp{flex:1;background:var(--bg);color:var(--fg);border:1px solid var(--line);border-radius:8px;padding:8px 10px;font-family:inherit}
button{background:var(--accent);border:none;color:#fff;padding:8px 16px;border-radius:8px;cursor:pointer;font-size:14px}
button:hover{opacity:.9}
.pair{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-top:12px}
.pair .lbl{color:var(--muted);font-size:12px;margin-bottom:4px}
.out{background:var(--bg);border:1px solid var(--line);border-radius:8px;padding:10px;min-height:36px;word-break:break-all;white-space:pre-wrap}
.muted{color:var(--muted)}.mb{margin-bottom:8px}
a{color:var(--accent)}
</style>
</head>
<body>
<div class="wrap">
  <div class="top">
    <div>
      <h1>🔐 PII 脱敏网关</h1>
      <div class="sub">在 LLM 网关前自动脱敏手机号/身份证，响应自动还原 · 管理端口 <span id="adminAddr">—</span></div>
    </div>
    <button class="theme-btn" id="themeBtn" onclick="toggleTheme()">🌙 深色</button>
  </div>

  <div class="grid" id="stats"></div>

  <div class="panel">
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
    <div class="muted">映射文件 <span id="cfgStore"></span> · 规则文件 <span id="cfgRules"></span></div>
    <div id="cfgMsg" style="margin-top:8px"></div>
  </div>

  <div class="panel">
    <h2>🧪 脱敏自测（不调模型，直接演示）</h2>
    <textarea id="selftest" placeholder="输入包含手机号/身份证的文本，例如：我的电话是13812345678，身份证110101199003071234"></textarea>
    <div style="margin-top:10px"><button onclick="runSelfTest()">运行自测</button></div>
    <div class="pair">
      <div><div class="lbl">脱敏后（发往上游）</div><div class="out" id="maskedOut">—</div></div>
      <div><div class="lbl">还原后（返回客户端）</div><div class="out" id="restoredOut">—</div></div>
    </div>
  </div>

  <div class="panel">
    <h2>🧩 正则规则 <span class="muted">(脱敏匹配规则，可增删，落盘持久)</span></h2>
    <div style="display:flex;gap:8px;margin-bottom:12px;flex-wrap:wrap">
      <input id="ruleName" class="inp" style="flex:1;min-width:140px" placeholder="规则名，如：银行卡号">
      <input id="rulePattern" class="inp" style="flex:2;min-width:220px" placeholder="正则，如：\\d{16,19}" onkeydown="if(event.key==='Enter')addRule()">
      <button onclick="addRule()">➕ 添加规则</button>
    </div>
    <div style="overflow-x:auto"><table>
      <thead><tr><th>规则名</th><th>正则</th><th>示例</th><th></th></tr></thead>
      <tbody id="ruleBody"></tbody>
    </table></div>
    <div class="muted" id="ruleEmpty" style="margin-top:10px">暂无规则</div>
  </div>

  <div class="panel">
    <h2>🗺️ 映射表 <span class="muted">(<span id="mapCount">0</span> 条 · 同一内容跨请求复用同一占位符)</span>
      <button style="float:right" onclick="clearMappings()">🗑️ 清除全部</button>
    </h2>
    <div style="display:flex;gap:8px;margin-bottom:12px">
      <input id="newReal" style="flex:1" class="inp" placeholder="手动添加真实值，如 1111 —— 自动分配占位符" onkeydown="if(event.key==='Enter')addMapping()">
      <button onclick="addMapping()">➕ 添加</button>
    </div>
    <div style="overflow-x:auto"><table>
      <thead><tr><th>占位符</th><th>真实值</th></tr></thead>
      <tbody id="mapBody"></tbody>
    </table></div>
    <div class="muted" id="mapEmpty" style="margin-top:10px">暂无映射</div>
  </div>

  <div class="panel">
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
  }catch(e){ $$('stats').innerHTML='<div class="card"><div class="k">管理端</div><div class="v err">'+e+'</div></div>'; }

  try{
    const logs = await j('/api/logs');
    $$('logCount').textContent = logs.length;
    $$('logBody').innerHTML = logs.map(l=>{
      const st = l.status>=500?'bad':(l.status>=400?'warn':'ok');
      const cls = l.status>=400?'err':'okc';
      return '<tr><td>'+l.time+'</td><td>'+l.client_ip+'</td><td>'+l.method+'</td><td>'+l.path+'</td>'+
        '<td class="'+cls+'">'+l.status+'</td><td>'+l.duration_ms+'ms</td>'+
        '<td>'+(l.masked_count||0)+'</td><td>'+(l.restored_count||0)+'</td>'+
        '<td>'+(l.residual?'<span class="pill bad">残留</span>':'—')+'</td></tr>';
    }).join('') || '<tr><td colspan="9" class="muted">暂无转发日志，等请求经过网关后自动出现。</td></tr>';
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

async function loadRules(){
  try{
    const d = await j('/api/rules');
    $$('ruleBody').innerHTML = d.rules.map(r=>'<tr><td>'+r.name+'</td><td><code>'+r.pattern+'</code></td><td>'+(r.sample||'—')+'</td><td><button style="padding:2px 10px" onclick="removeRule('+JSON.stringify(r.name)+')">删</button></td></tr>').join('');
    $$('ruleEmpty').style.display = d.rules.length? 'none':'block';
  }catch(e){}
}
async function addRule(){
  const name = $$('ruleName').value.trim(), pattern = $$('rulePattern').value.trim();
  if(!name||!pattern){ alert('请填写规则名和正则'); return; }
  try{
    await j('/api/rules',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name,pattern})});
    $$('ruleName').value=''; $$('rulePattern').value=''; loadRules();
  }catch(e){ alert('添加失败: '+e) }
}
async function removeRule(name){
  if(!confirm('删除规则「'+name+'」？')) return;
  try{ await j('/api/rules/remove',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name})}); loadRules(); }
  catch(e){ alert('删除失败: '+e) }
}
async function loadMappings(){
  try{
    const d = await j('/api/mappings');
    $$('mapCount').textContent = d.size;
    $$('mapBody').innerHTML = d.entries.map(e=>'<tr><td>'+e.placeholder+'</td><td>'+e.real+'</td></tr>').join('');
    $$('mapEmpty').style.display = d.size? 'none':'block';
  }catch(e){}
}
async function addMapping(){
  const real = $$('newReal').value.trim();
  if(!real){ alert('请输入要添加的真实值'); return; }
  try{
    const r = await j('/api/mappings',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({real})});
    alert('已'+(r.new?'新增':'复用')+'映射：'+r.real+' → '+r.placeholder);
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

function applyTheme(t){
  document.body.classList.toggle('theme-light', t==='light');
  localStorage.setItem('pii_theme', t);
  $$('themeBtn').textContent = t==='light'? '☀️ 浅色' : '🌙 深色';
}
function toggleTheme(){ applyTheme(localStorage.getItem('pii_theme')==='light'?'dark':'light'); }

async function loadConfig(){
  try{
    const c = await j('/api/config');
    $$('cfgTarget').value = c.forward_target;
    $$('cfgListen').value = c.listen_addr;
    $$('cfgAdmin').value = c.admin_addr;
    $$('cfgStore').textContent = c.store_file;
    $$('cfgRules').textContent = c.rules_file;
  }catch(e){}
}
async function saveConfig(){
  const body = {
    forward_target: $$('cfgTarget').value.trim(),
    listen_addr: $$('cfgListen').value.trim(),
    admin_addr: $$('cfgAdmin').value.trim()
  };
  try{
    const r = await j('/api/config',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
    $$('cfgMsg').innerHTML = r.restart_required? '<span class="err">已保存：端口改动需重启后生效</span>' : '<span class="okc">已保存：转发目标已生效</span>';
    loadConfig(); refresh();
  }catch(e){ $$('cfgMsg').innerHTML='<span class="err">保存失败: '+e+'</span>' }
}

refresh();
setInterval(()=>{ refresh(); loadMappings(); loadRules(); loadConfig(); }, 1500);
loadMappings(); loadRules(); loadConfig();
applyTheme(localStorage.getItem('pii_theme')||'dark');
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
