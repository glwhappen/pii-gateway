package main

import (
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
)

// 占位符格式：[[PID_<n>]]，只用字母数字下划线，不破坏 JSON，
// 且足够独特，模型正常情况下会原样返回、便于还原。
var placeholderRe = regexp.MustCompile(`\[\[PID_[0-9]+\]\]`)

// 中国大陆手机号：1[3-9] 开头共 11 位
var phoneRe = regexp.MustCompile(`1[3-9][0-9]{9}`)

// 身份证号：17 位数字 + 1 位数字或 X/x
var idCardRe = regexp.MustCompile(`(?i)[0-9]{17}[0-9X]`)

var pidCounter atomic.Uint64

// piiStore 保存 真实值 <-> 占位符 的全局映射，保证同一内容跨请求复用同一占位符。
// 进程内存级持久：同一内容不管对话多少次都用同一个占位符；进程重启后清空。
// （如需跨重启持久可落盘，见 README 局限一节。）
type piiStore struct {
	mu      sync.Mutex
	real2ph map[string]string
	ph2real map[string]string
}

var globalStore = newPIIStore()

func newPIIStore() *piiStore {
	return &piiStore{real2ph: make(map[string]string), ph2real: make(map[string]string)}
}

func (s *piiStore) lookup(real string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ph, ok := s.real2ph[real]
	return ph, ok
}

func (s *piiStore) remember(real, ph string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.real2ph[real] = ph
	s.ph2real[ph] = real
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

// clear 清空全部映射。
func (s *piiStore) clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.real2ph = make(map[string]string)
	s.ph2real = make(map[string]string)
}

// phNumber 解析占位符里的编号 [[PID_123]] -> 123。
func phNumber(ph string) int {
	s := strings.TrimPrefix(ph, "[[PID_")
	s = strings.TrimSuffix(s, "]]")
	n, _ := strconv.Atoi(s)
	return n
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
// 返回掩码后的字节和映射。body 可为二进制/文本，仅对 UTF-8 文本敏感。
func mask(body []byte, m *mapping) []byte {
	replaced := idCardRe.ReplaceAllStringFunc(string(body), func(s string) string {
		return maskOne(s, m)
	})
	replaced = phoneRe.ReplaceAllStringFunc(replaced, func(s string) string {
		return maskOne(s, m)
	})
	return []byte(replaced)
}

func maskOne(real string, m *mapping) string {
	// 已替换过的占位符不再重复处理
	if placeholderRe.MatchString(real) {
		return real
	}
	// 同一内容跨请求复用同一占位符（确定性脱敏）
	ph, ok := globalStore.lookup(real)
	if !ok {
		n := pidCounter.Add(1)
		ph = "[[PID_" + strconv.FormatUint(n, 10) + "]]"
		globalStore.remember(real, ph)
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
