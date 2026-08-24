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
	rulesList = []map[string]string{
		{"name": "中国大陆手机号", "pattern": `1[3-9][0-9]{9}`, "sample": "13812345678"},
		{"name": "中国大陆身份证", "pattern": `[0-9]{17}[0-9X]`, "sample": "110101199003071234"},
	}
)

// startAdmin 启动管理服务（独立端口，不干扰转发）。
func startAdmin() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", serveAdminPage)
	mux.HandleFunc("/api/health", adminHealth)
	mux.HandleFunc("/api/logs", adminLogs)
	mux.HandleFunc("/api/rules", adminRules)
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
		"target":       targetBase,
		"admin":        adminAddr,
		"log_entries":  logs.count(),
		"mapping_size": globalStore.size(),
		"now":          time.Now().Format(time.RFC3339),
	})
}

func adminLogs(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, logs.list())
}

func adminRules(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, rulesList)
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
*{box-sizing:border-box}body{margin:0;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;background:var(--bg);color:var(--fg);font-size:14px}
.wrap{max-width:1100px;margin:0 auto;padding:24px}
h1{font-size:20px;margin:0 0 4px}.sub{color:var(--muted);margin-bottom:20px}
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
  <h1>🔐 PII 脱敏网关</h1>
  <div class="sub">在 LLM 网关前自动脱敏手机号/身份证，响应自动还原 · 管理端口 <span id="adminAddr">—</span></div>

  <div class="grid" id="stats"></div>

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

refresh();
setInterval(()=>{ refresh(); loadMappings(); }, 1500);
loadMappings();
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
