package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
)

var pidCounter atomic.Uint64

// piiStore 保存 真实值 <-> 占位符 的全局映射，保证同一内容跨请求复用同一占位符。
// 进程内存级持久：同一内容不管对话多少次都用同一个占位符；进程重启后清空。
// （如需跨重启持久可落盘，见 README 局限一节。）
type piiStore struct {
	mu      sync.Mutex
	real2ph map[string]string
	ph2real map[string]string
	ignored map[string]bool // 被忽略的真实值：不再参与脱敏（保留记录，可取消忽略）
	persist bool            // false 则不落盘（用于演示等隔离场景）
}

var globalStore = newPIIStore()

// piiStoreFile 映射落盘路径（含 PII，权限 0600，不提交 git）。
var piiStoreFile = envOr("PII_STORE_FILE", "pii-store.json")

func newPIIStore() *piiStore {
	return &piiStore{real2ph: make(map[string]string), ph2real: make(map[string]string), ignored: make(map[string]bool), persist: true}
}

// newNoPersistStore 返回不落盘的隔离 store（演示用，避免污染生产映射/磁盘）。
func newNoPersistStore() *piiStore {
	return &piiStore{real2ph: make(map[string]string), ph2real: make(map[string]string), ignored: make(map[string]bool), persist: false}
}

func (s *piiStore) lookup(real string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ph, ok := s.real2ph[real]
	return ph, ok
}

// lookupByPh 按占位符反查真实值（用于响应还原时对全局持久映射的兜底查询）。
func (s *piiStore) lookupByPh(ph string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	real, ok := s.ph2real[ph]
	return real, ok
}

func (s *piiStore) remember(real, ph string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.real2ph[real]; ok {
		return false
	}
	s.real2ph[real] = ph
	s.ph2real[ph] = real
	return true
}

// loadFile 从磁盘加载映射（首次无文件则忽略），并恢复 pid 计数器避免冲突。
func (s *piiStore) loadFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var raw struct {
		Real2ph map[string]string `json:"real2ph"`
		Ignored []string          `json:"ignored,omitempty"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.real2ph = raw.Real2ph
	s.ph2real = make(map[string]string, len(raw.Real2ph))
	s.ignored = make(map[string]bool, len(raw.Ignored))
	for _, real := range raw.Ignored {
		s.ignored[real] = true
	}
	var max uint64
	for real, ph := range s.real2ph {
		s.ph2real[ph] = real
		if n := uint64(phNumber(ph)); n > max {
			max = n
		}
	}
	pidCounter.Store(max)
	return nil
}

// saveFile 原子落盘（写临时文件后 rename），权限 0600。
func (s *piiStore) saveFile(path string) error {
	s.mu.Lock()
	ignoredArr := make([]string, 0, len(s.ignored))
	for real := range s.ignored {
		ignoredArr = append(ignoredArr, real)
	}
	sort.Strings(ignoredArr)
	data, err := json.Marshal(map[string]any{"real2ph": s.real2ph, "ignored": ignoredArr})
	s.mu.Unlock()
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func (s *piiStore) size() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.real2ph)
}

// mappingEntry 一条 占位符 <-> 真实值 映射（供管理面板展示）。
type mappingEntry struct {
	Placeholder string `json:"placeholder"`
	Real        string `json:"real"`
}

// list 返回全部映射，按占位符编号升序。
func (s *piiStore) list() []mappingEntry {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]mappingEntry, 0, len(s.real2ph))
	for real, ph := range s.real2ph {
		out = append(out, mappingEntry{Placeholder: ph, Real: real})
	}
	sort.Slice(out, func(i, j int) bool {
		return phNumber(out[i].Placeholder) < phNumber(out[j].Placeholder)
	})
	return out
}

// delete 按占位符删除单条映射并落盘。返回被删除的真实值；占位符不存在时返回 false。
func (s *piiStore) delete(ph string) (real string, ok bool) {
	s.mu.Lock()
	real, ok = s.ph2real[ph]
	if !ok {
		s.mu.Unlock()
		return "", false
	}
	delete(s.ph2real, ph)
	delete(s.real2ph, real)
	delete(s.ignored, real)
	s.mu.Unlock()
	if err := s.saveFile(piiStoreFile); err != nil {
		log.Printf("save pii store: %v", err)
	}
	return real, true
}

// clear 清空全部映射并落盘。
func (s *piiStore) clear() {
	s.mu.Lock()
	s.real2ph = make(map[string]string)
	s.ph2real = make(map[string]string)
	s.ignored = make(map[string]bool)
	s.mu.Unlock()
	_ = s.saveFile(piiStoreFile)
}

// isIgnored 判断某真实值是否已被忽略（忽略后不再脱敏）。
func (s *piiStore) isIgnored(real string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ignored[real]
}

// setIgnored 按占位符设置忽略状态（忽略后该真实值不再脱敏，保留记录可恢复）。
func (s *piiStore) setIgnored(ph string, ig bool) error {
	s.mu.Lock()
	real, ok := s.ph2real[ph]
	if !ok {
		s.mu.Unlock()
		return fmt.Errorf("占位符 %q 不存在", ph)
	}
	if ig {
		s.ignored[real] = true
	} else {
		delete(s.ignored, real)
	}
	s.mu.Unlock()
	return s.saveFile(piiStoreFile)
}

// ResetPIIStore 清空全局映射（供测试或管理面板调用）。
func ResetPIIStore() {
	globalStore = newPIIStore()
}

// mapping 保存 占位符 -> 真实值，用于响应还原。
type mapping struct {
	// 按插入顺序记录，便于调试
	items []string // 交替 ph, real
	real  map[string]string
	// Restored 统计实际还原成功的占位符次数（供日志）
	Restored int
	// Residual 标记响应还原后是否仍残留占位符（供日志）
	Residual bool
}

func newMapping() *mapping {
	return &mapping{real: make(map[string]string)}
}

// mask 将 body 中的 PII 替换为占位符（使用全局持久 store）。
func mask(body []byte, m *mapping) []byte {
	return maskWith(globalStore, body, m)
}

// maskWith 与 mask 相同，但使用传入的 store（可隔离、可禁止落盘）。
// body 为合法 JSON 时仅对字符串值（value）脱敏，避免规则正则把 JSON 里的裸数字字段
// （如 "seed":13812345678、"top_p":13812345678、时间戳等）替换成占位符后破坏 JSON 结构；
// 非 JSON（或 JSON 解析异常）时回退到全文本替换。
func maskWith(st *piiStore, body []byte, m *mapping) []byte {
	if json.Valid(body) {
		if out, ok := maskJSONStrings(st, body, m); ok {
			return out
		}
	}
	return []byte(maskText(st, string(body), m))
}

// maskText 对单个文本串执行三步脱敏：
// 1. 按全局规则（可配置正则）逐个替换；
// 2. 敏感名单（姓名等）出现即替换；
// 3. 手动添加的自定义值（不匹配任何规则）出现即替换。
func maskText(st *piiStore, s string, m *mapping) string {
	s = maskRules(st, s, m)
	// 敏感名单（姓名等）：正文出现即掩码，确定性复用同一占位符。
	// 按长度降序处理，避免短名先替换长名内的子串。
	for _, nm := range sortedNames() {
		if st.isIgnored(nm) {
			continue // 该词已被忽略，不脱敏
		}
		if !strings.Contains(s, nm) {
			continue
		}
		ph, ok := st.lookup(nm)
		if !ok {
			n := pidCounter.Add(1)
			ph = phFor("NAME", n)
			if st.remember(nm, ph) && st.persist {
				_ = st.saveFile(piiStoreFile)
			}
		}
		s = strings.ReplaceAll(s, nm, ph)
		if _, exists := m.real[ph]; !exists {
			m.real[ph] = nm
			m.items = append(m.items, ph, nm)
		}
	}
	// 手动添加的自定义值：body 中出现即替换为其占位符。
	// 注意：manualEntries 来自 map 迭代顺序不确定，必须按真实值长度降序排序后再替换，
	// 否则短值（如 123）可能先替换长值（如 1234）里的子串，把 1234 拆开残留明文。
	// 长值优先 + ReplaceAll 贪心替换，保证任一被包含的短值不会破坏长值。
	manual := st.manualEntries()
	sort.Slice(manual, func(i, j int) bool { return len(manual[i].Real) > len(manual[j].Real) })
	for _, e := range manual {
		if strings.Contains(s, e.Real) {
			s = strings.ReplaceAll(s, e.Real, e.Placeholder)
			if _, ok := m.real[e.Placeholder]; !ok {
				m.real[e.Placeholder] = e.Real
				m.items = append(m.items, e.Placeholder, e.Real)
			}
		}
	}
	return s
}

// maskJSONStrings 对合法 JSON body 做保序脱敏：只替换字符串值（value）中的 PII，
// 对象的 key、数字/布尔/null 字段、结构符号与空白均保留原始字节（含精度与顺序）。
// 返回 (脱敏后的 body, 是否成功)。任何解析异常均返回 (nil, false) 由调用方回退。
func maskJSONStrings(st *piiStore, body []byte, m *mapping) ([]byte, bool) {
	dec := json.NewDecoder(bytes.NewReader(body))
	var out bytes.Buffer
	prev := dec.InputOffset()
	// 上下文栈：每层对象记录下一个字符串 token 是 key 还是 value；数组元素均为 value。
	const (
		ctxObjExpectKey   = 1
		ctxObjExpectValue = 2
		ctxArray          = 3
	)
	var stack []int
	for {
		offBefore := dec.InputOffset()
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, false
		}
		off := dec.InputOffset()
		raw := body[offBefore:off]
		// raw 可能含 token 前导空白与结构字符（: ,），分离出需原样保留的前缀与 token 本体
		trim := len(raw) - len(bytes.TrimLeft(raw, " \t\r\n:,"))
		prefix := raw[:trim]

		isValue := len(stack) == 0 || stack[len(stack)-1] != ctxObjExpectKey
		switch t := tok.(type) {
		case json.Delim:
			switch t {
			case '{':
				stack = append(stack, ctxObjExpectKey)
			case '[':
				stack = append(stack, ctxArray)
			case '}':
				stack = stack[:len(stack)-1]
			case ']':
				stack = stack[:len(stack)-1]
			}
			out.Write(raw)
		case string:
			if !isValue {
				// 对象 key：原样保留（key 被替换会破坏结构语义）
				out.Write(raw)
				stack[len(stack)-1] = ctxObjExpectValue
				prev = off
				continue
			}
			masked := maskText(st, t, m)
			if masked == t {
				out.Write(raw)
			} else {
				out.Write(prefix)
				out.Write(jsonEscapeString(masked))
			}
			if len(stack) > 0 && stack[len(stack)-1] == ctxObjExpectValue {
				stack[len(stack)-1] = ctxObjExpectKey
			}
		default:
			// 数字/布尔/null：原字节保留
			out.Write(raw)
			if len(stack) > 0 && stack[len(stack)-1] == ctxObjExpectValue {
				stack[len(stack)-1] = ctxObjExpectKey
			}
		}
		prev = off
	}
	out.Write(body[prev:])
	return out.Bytes(), true
}

// sortedNames 返回去重、按长度降序的敏感名单（长名优先，避免短名先替换长名子串）。
func sortedNames() []string {
	seen := map[string]bool{}
	var out []string
	for _, nm := range namesList {
		nm = strings.TrimSpace(nm)
		if nm == "" || seen[nm] {
			continue
		}
		seen[nm] = true
		out = append(out, nm)
	}
	sort.Slice(out, func(i, j int) bool { return len(out[i]) > len(out[j]) })
	return out
}

// manualEntries 返回 store 中「不匹配任何正则规则」的手动自定义映射。
func (s *piiStore) manualEntries() []mappingEntry {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []mappingEntry
	for real, ph := range s.real2ph {
		if s.ignored[real] {
			continue // 已被忽略，不参与手动替换
		}
		if globalRules.matches(real) {
			continue // 这类已由正则规则处理
		}
		out = append(out, mappingEntry{Placeholder: ph, Real: real})
	}
	return out
}

// maskRules 用所有正则规则扫描正文，找出全部匹配区间，重叠时保留「最长」的匹配
// （更精确），然后按原文位置从左到右替换。避免短规则（如银行卡 4\d{15}）截断
// 长规则（如 18 位身份证 [0-9]{17}[0-9X]）。
func maskRules(st *piiStore, s string, m *mapping) string {
	type span struct {
		start, end int
		real, typ  string
	}
	var spans []span
	for _, r := range globalRules.all() {
		if r.re == nil {
			continue
		}
		for _, loc := range r.re.FindAllStringIndex(s, -1) {
			spans = append(spans, span{loc[0], loc[1], s[loc[0]:loc[1]], r.Type})
		}
	}
	if len(spans) == 0 {
		return s
	}
	// 长度降序，长度相同时靠左优先（稳定）。
	sort.Slice(spans, func(i, j int) bool {
		if spans[i].end-spans[i].start != spans[j].end-spans[j].start {
			return spans[i].end-spans[i].start > spans[j].end-spans[j].start
		}
		return spans[i].start < spans[j].start
	})
	// 从长到短筛出「不与其他已采纳区间重叠」的最终区间。
	accepted := make([]span, 0, len(spans))
	for _, sp := range spans {
		overlap := false
		for _, a := range accepted {
			if sp.start < a.end && a.start < sp.end {
				overlap = true
				break
			}
		}
		if !overlap {
			accepted = append(accepted, sp)
		}
	}
	// 按原文位置从左到右替换。
	sort.Slice(accepted, func(i, j int) bool { return accepted[i].start < accepted[j].start })
	var b strings.Builder
	b.Grow(len(s))
	prev := 0
	for _, sp := range accepted {
		if sp.start < prev {
			continue
		}
		b.WriteString(s[prev:sp.start])
		b.WriteString(maskOne(st, sp.real, m, sp.typ))
		prev = sp.end
	}
	b.WriteString(s[prev:])
	return b.String()
}

func maskOne(st *piiStore, real string, m *mapping, typ string) string {
	// 已替换过的占位符不再重复处理
	if placeholderRe.MatchString(real) {
		return real
	}
	// 该真实值已被忽略：不脱敏，保留明文
	if st.isIgnored(real) {
		return real
	}
	// 同一内容跨请求复用同一占位符（确定性脱敏）
	ph, ok := st.lookup(real)
	if !ok {
		n := pidCounter.Add(1)
		ph = phFor(typ, n)
		if st.remember(real, ph) && st.persist {
			_ = st.saveFile(piiStoreFile) // 新增映射立即落盘
		}
	}
	// 记入本请求 mapping（还原用）；同一真实值只记一次，避免重复计数
	if _, exists := m.real[ph]; !exists {
		m.real[ph] = real
		m.items = append(m.items, ph, real)
	}
	return ph
}

// MaskedCount 返回本次请求脱敏的 PII 处数。
func (m *mapping) MaskedCount() int { return len(m.items) / 2 }

// restore 将 data 中的占位符还原为真实值。
// 对每个占位符做普通字符串替换（占位符不含 JSON 特殊字符，安全）。
func restore(data []byte, m *mapping) []byte {
	if m == nil {
		return data
	}
	s := string(data)
	// 上游用 JSON 序列化响应时会把 < > 转义成 \u003c \u003e，使占位符 <<PII:...>> 变形、
	// 正则匹配不到而无法还原。这里先把转义尖括号反转义回 < >，再还原占位符。
	s = strings.ReplaceAll(s, `\u003c`, "<")
	s = strings.ReplaceAll(s, `\u003e`, ">")
	// 优先还原长的（身份证占位符与手机号长度相同，但保守起见逐个替换）
	for _, ph := range allPlaceholders(s) {
		// 先查本次请求内脱敏建立的映射（m.real）；跨请求/上下文压缩时明文来源可能已不在
		// 本次 body，查不到则回退到全局持久映射（ph2real），保证已脱敏过的名字也能还原。
		real, ok := m.real[ph]
		if !ok {
			real, ok = globalStore.lookupByPh(ph)
		}
		if ok {
			s = strings.ReplaceAll(s, ph, real)
			m.Restored++
		}
	}
	return []byte(s)
}

// allPlaceholders 从一段文本中提取所有出现的占位符（去重、按出现顺序）。
func allPlaceholders(s string) []string {
	var out []string
	seen := map[string]bool{}
	for _, ph := range placeholderRe.FindAllString(s, -1) {
		if !seen[ph] {
			seen[ph] = true
			out = append(out, ph)
		}
	}
	return out
}

// jsonEscapeString 将字符串编码为带引号的 JSON 字符串字面量，仅转义 JSON 必需字符，
// 保留 < > 原样（占位符 <<PII:...>> 依赖尖括号不被 \u003c 转义，便于响应还原匹配）。
func jsonEscapeString(s string) []byte {
	var b bytes.Buffer
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if r < 0x20 {
				fmt.Fprintf(&b, `\u%04x`, r)
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
	return b.Bytes()
}
