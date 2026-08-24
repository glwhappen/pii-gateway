package main

import (
	"encoding/json"
	"log"
	"net/http"
)

// demoAddr 演示站点端口；为空则不启用。演示页完全独立、纯内存、不落盘任何 PII。
var demoAddr = envOr("PII_DEMO", "")

// startDemo 启动独立演示站点（可公网反代，仅展示脱敏/还原，不暴露管理功能）。
func startDemo() {
	if demoAddr == "" {
		return
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", serveDemoPage)
	mux.HandleFunc("/api/demo", demoMask)
	log.Printf("pii-gateway demo page on %s", demoAddr)
	if err := http.ListenAndServe(demoAddr, mux); err != nil {
		log.Printf("demo server: %v", err)
	}
}

// demoMask 纯内存脱敏演示：使用隔离 store，不写映射历史、不落盘任何数据。
func demoMask(w http.ResponseWriter, r *http.Request) {
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
	st := newNoPersistStore() // 隔离 store，仅本次内存，不污染生产
	m := newMapping()
	masked := maskWith(st, []byte(req.Text), m)
	restored := restore(masked, m)
	writeJSON(w, map[string]any{
		"masked":   string(masked),
		"restored": string(restored),
		"count":    m.MaskedCount(),
	})
}

const demoPageHTML = `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>PII 脱敏演示</title>
<style>
*{box-sizing:border-box}
body{margin:0;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI','Noto Sans',sans-serif;background:#f7f8fa;color:#101828;font-size:14px;line-height:1.6}
.wrap{max-width:760px;margin:0 auto;padding:32px 20px}
h1{font-size:24px;margin:0 0 4px}
.sub{color:#667085;margin-bottom:22px}
.card{background:#fff;border:1px solid #e4e7ec;border-radius:12px;padding:20px;margin-bottom:16px;box-shadow:0 1px 3px rgba(16,24,40,.08)}
textarea{width:100%;min-height:96px;background:#f9fafb;border:1px solid #d0d5dd;border-radius:8px;padding:10px 12px;font-size:14px;resize:vertical}
textarea:focus{outline:none;border-color:#4f46e5;box-shadow:0 0 0 3px #eef4ff}
button{background:#4f46e5;border:none;color:#fff;padding:9px 18px;border-radius:8px;cursor:pointer;font-size:14px}
button.secondary{background:#eef4ff;color:#4f46e5;border:1px solid #c7d2fe}
button:hover{filter:brightness(.97)}
.btns{display:flex;gap:8px;flex-wrap:wrap;margin-top:12px}
.lbl{color:#667085;font-size:12px;font-weight:600;margin-bottom:6px}
.out{background:#f9fafb;border:1px solid #e4e7ec;border-radius:8px;padding:12px;min-height:44px;word-break:break-all;white-space:pre-wrap;font-family:ui-monospace,Menlo,Consolas,monospace;font-size:13px}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-top:14px}
.tag{display:inline-block;background:#eef4ff;color:#4f46e5;border:1px solid #c7d2fe;border-radius:999px;padding:2px 10px;font-size:12px;margin:2px}
@media(max-width:640px){.grid{grid-template-columns:1fr}}
</style>
</head>
<body>
<div class="wrap">
  <h1>🔐 PII 脱敏网关 · 演示</h1>
  <div class="sub">在 LLM 网关前自动脱敏手机号/身份证等隐私信息，响应自动还原。<b>本页仅演示，不保存任何数据。</b></div>

  <div class="card">
    <div class="lbl">输入一段文本（可含手机号 / 身份证 / 邮箱 / 银行卡等）</div>
    <textarea id="text" placeholder="例如：我的电话是13812345678，身份证110101199003071234"></textarea>
    <div class="btns">
      <button onclick="run()">▶ 运行演示</button>
      <button class="secondary" onclick="sample('我的电话是13812345678，身份证110101199003071234')">📱 手机号/身份证</button>
      <button class="secondary" onclick="sample('联系张三：13812345678，邮箱zs@test.com，车牌粤B12345')">🧾 混合信息</button>
      <button class="secondary" onclick="sample('服务器IP 192.168.1.100，MAC aa:bb:cc:dd:ee:ff，OpenAI key sk-abcdefghijklmnopqrstuvwxyz123456')">🌐 网络/凭证</button>
    </div>
  </div>

  <div class="card" id="result" style="display:none">
    <div class="grid">
      <div><div class="lbl">脱敏后（发往上游）</div><div class="out" id="masked"></div></div>
      <div><div class="lbl">还原后（返回客户端）</div><div class="out" id="restored"></div></div>
    </div>
    <div style="margin-top:12px" id="types"></div>
  </div>

  <div class="sub" style="margin-top:20px">纯内存演示，关闭页面即清除，不留任何痕迹。</div>
</div>
<script>
const $=id=>document.getElementById(id);
function sample(t){ $('text').value=t; run(); }
async function run(){
  const text=$('text').value;
  if(!text){ alert('请先输入文本'); return; }
  $('result').style.display='block';
  $('masked').textContent='处理中…';
  try{
    const r=await (await fetch('/api/demo',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({text})})).json();
    $('masked').textContent=r.masked;
    $('restored').textContent=r.restored;
    const types=[...new Set((r.masked.match(/<<PII:([A-Z0-9_]+):/g)||[]).map(x=>x.slice(6,-1)))];
    $('types').innerHTML='命中类型：'+types.map(t=>'<span class="tag">'+t+'</span>').join('')+(r.count? '<span style="color:#667085;margin-left:8px;font-size:12px">共脱敏 '+r.count+' 处</span>':'');
  }catch(e){ $('masked').textContent='错误: '+e; }
}
</script>
</body>
</html>
`

func serveDemoPage(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(demoPageHTML))
}
