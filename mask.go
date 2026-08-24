package main

import (
	"encoding/json"
	"fmt"
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
}

var globalStore = newPIIStore()

// piiStoreFile 映射落盘路径（含 PII，权限 0600，不提交 git）。
var piiStoreFile = envOr("PII_STORE_FILE", "pii-store.json")

func newPIIStore() *piiStore {
	return &piiStore{real2ph: make(map[string]string), ph2real: make(map[string]string), ignored: make(map[string]bool)}
}

func (s *piiStore) lookup(real string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ph, ok := s.real2ph[real]
	return ph, ok
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

// mask 将 body 中的 PII 替换为占位符，并记录 占位符->真实值 映射。
// 1. 按全局规则（可配置正则，默认手机号/身份证）逐个替换；
// 2. 手动添加的自定义真实值（不匹配任何规则，如 1111）也在 body 出现时替换。
func mask(body []byte, m *mapping) []byte {
	s := string(body)
	for _, r := range globalRules.all() {
		if r.re == nil {
			continue
		}
		typ := r.Type
		s = r.re.ReplaceAllStringFunc(s, func(x string) string {
			return maskOne(x, m, typ)
		})
	}
	// 敏感名单（姓名等）：正文出现即掩码，确定性复用同一占位符。
	// 按长度降序处理，避免短名先替换长名内的子串。
	for _, nm := range sortedNames() {
		if globalStore.isIgnored(nm) {
			continue // 该词已被忽略，不脱敏
		}
		if !strings.Contains(s, nm) {
			continue
		}
		ph, ok := globalStore.lookup(nm)
		if !ok {
			n := pidCounter.Add(1)
			ph = phFor("NAME", n)
			if globalStore.remember(nm, ph) {
				_ = globalStore.saveFile(piiStoreFile)
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
	manual := globalStore.manualEntries()
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
	return []byte(s)
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

func maskOne(real string, m *mapping, typ string) string {
	// 已替换过的占位符不再重复处理
	if placeholderRe.MatchString(real) {
		return real
	}
	// 该真实值已被忽略：不脱敏，保留明文
	if globalStore.isIgnored(real) {
		return real
	}
	// 同一内容跨请求复用同一占位符（确定性脱敏）
	ph, ok := globalStore.lookup(real)
	if !ok {
		n := pidCounter.Add(1)
		ph = phFor(typ, n)
		if globalStore.remember(real, ph) {
			_ = globalStore.saveFile(piiStoreFile) // 新增映射立即落盘
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
	if m == nil || len(m.real) == 0 {
		return data
	}
	s := string(data)
	// 优先还原长的（身份证占位符与手机号长度相同，但保守起见逐个替换）
	for _, ph := range allPlaceholders(s) {
		if real, ok := m.real[ph]; ok {
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
