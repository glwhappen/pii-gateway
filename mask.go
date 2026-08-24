package main

import (
	"encoding/json"
	"os"
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

// piiStoreFile 映射落盘路径（含 PII，权限 0600，不提交 git）。
var piiStoreFile = envOr("PII_STORE_FILE", "pii-store.json")

func newPIIStore() *piiStore {
	return &piiStore{real2ph: make(map[string]string), ph2real: make(map[string]string)}
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
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.real2ph = raw.Real2ph
	s.ph2real = make(map[string]string, len(raw.Real2ph))
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
	data, err := json.Marshal(map[string]any{"real2ph": s.real2ph})
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
	s.mu.Unlock()
	_ = s.saveFile(piiStoreFile)
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
// 1. 内置正则（手机号/身份证）替换；
// 2. 手动添加的自定义真实值（不匹配内置正则，如 1111）也在 body 出现时替换。
func mask(body []byte, m *mapping) []byte {
	s := string(body)
	s = idCardRe.ReplaceAllStringFunc(s, func(x string) string {
		return maskOne(x, m)
	})
	s = phoneRe.ReplaceAllStringFunc(s, func(x string) string {
		return maskOne(x, m)
	})
	// 手动添加的自定义值：body 中出现即替换为其占位符
	for _, e := range globalStore.manualEntries() {
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

// manualEntries 返回 store 中「不匹配内置正则」的手动自定义映射。
func (s *piiStore) manualEntries() []mappingEntry {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []mappingEntry
	for real, ph := range s.real2ph {
		if phoneRe.MatchString(real) || idCardRe.MatchString(real) {
			continue // 这类已由内置正则处理
		}
		out = append(out, mappingEntry{Placeholder: ph, Real: real})
	}
	return out
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
