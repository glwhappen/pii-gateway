package main

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
	"sync"
)

// Rule 一条脱敏正则规则。
type Rule struct {
	Name    string         `json:"name"`
	Type    string         `json:"type,omitempty"` // 占位符类型标签，如 PHONE/IDCARD；空则按 UNKNOWN
	Pattern string         `json:"pattern"`
	Sample  string         `json:"sample,omitempty"`
	re      *regexp.Regexp // 不序列化
}

// ruleStore 脱敏正则规则集合，可增删，落盘持久化。
type ruleStore struct {
	mu    sync.RWMutex
	rules []Rule
}

var globalRules = newRuleStore()

// rulesFile 规则落盘路径。
var rulesFile = envOr("PII_RULES_FILE", "rules.json")

func defaultRules() []Rule {
	return []Rule{
		// 银行卡放最前（BIN 前缀，避免 19 位卡被身份证规则截断）
		{Name: "银行卡号", Type: "BANKCARD", Pattern: `(?:62\d{14,17}|4\d{15}|5[1-5]\d{14})`, Sample: "6222021234567890123"},
		{Name: "中国大陆身份证", Type: "IDCARD", Pattern: `(?i)[0-9]{17}[0-9X]`, Sample: "110101199003071234"},
		{Name: "中国大陆手机号", Type: "PHONE", Pattern: `1[3-9][0-9]{9}`, Sample: "13812345678"},
		{Name: "邮箱", Type: "EMAIL", Pattern: `[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}`, Sample: "abc@test.com"},
		{Name: "中国大陆车牌", Type: "PLATE", Pattern: `[京津沪渝冀豫云辽黑湘皖鲁新苏浙赣鄂桂甘晋蒙陕吉闽贵粤青藏川宁琼使领][A-HJ-NP-Z][A-HJ-NP-Z0-9]{5,6}`, Sample: "粤B12345"},
		{Name: "固定电话", Type: "LANDLINE", Pattern: `0\d{2,3}-?\d{7,8}`, Sample: "0755-12345678"},
		{Name: "中国护照", Type: "PASSPORT", Pattern: `(?i)[eghpsd]\d{8}`, Sample: "E12345678"},
		// ---- 补充规则：证件 / 信用代码 / 网络 / 凭证类（覆盖更广）----
		{Name: "港澳通行证", Type: "HKMO_PASS", Pattern: `\b[HM]\d{8,10}\b`, Sample: "H12345678"},
		{Name: "统一社会信用代码", Type: "CREDIT_CODE", Pattern: `(?i)\b[0-9A-HJ-NPQRTUWXY]{2}\d{6}[0-9A-HJ-NPQRTUWXY]{10}\b`, Sample: "91310115MA1K3N5D6X"},
		{Name: "组织机构代码", Type: "ORG_CODE", Pattern: `\b[0-9A-Z]{8}-?[0-9X]\b`, Sample: "12345678-9"},
		{Name: "IPv4 地址", Type: "IPV4", Pattern: `\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b`, Sample: "192.168.1.100"},
		{Name: "IPv6 地址", Type: "IPV6", Pattern: `(?i)\b(?:(?:[0-9a-f]{1,4}:){7}[0-9a-f]{1,4}|(?:[0-9a-f]{1,4}:){1,7}:|(?:[0-9a-f]{1,4}:){1,6}:[0-9a-f]{1,4}|(?:[0-9a-f]{1,4}:){1,5}(?::[0-9a-f]{1,4}){1,2}|(?:[0-9a-f]{1,4}:){1,4}(?::[0-9a-f]{1,4}){1,3}|(?:[0-9a-f]{1,4}:){1,3}(?::[0-9a-f]{1,4}){1,4}|(?:[0-9a-f]{1,4}:){1,2}(?::[0-9a-f]{1,4}){1,5}|[0-9a-f]{1,4}:(?::[0-9a-f]{1,4}){1,6})\b`, Sample: "2001:0db8:85a3:0000:0000:8a2e:0370:7334"},
		{Name: "MAC 地址", Type: "MAC", Pattern: `(?i)\b(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}\b`, Sample: "aa:bb:cc:dd:ee:ff"},
		{Name: "JWT", Type: "JWT", Pattern: `\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b`, Sample: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"},
		{Name: "Bearer Token", Type: "BEARER", Pattern: `(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{20,}\b`, Sample: "Bearer eyJ0eXAiOiJKV1QifQ.abc.def"},
		{Name: "模型/OpenAI API Key", Type: "API_KEY", Pattern: `(?i)\b(?:sk-[A-Za-z0-9_-]{16,}|sk-ant-[A-Za-z0-9_-]{20,})\b`, Sample: "sk-abcdefghijklmnopqrstuvwxyz123456"},
		{Name: "GitHub Token", Type: "GITHUB_TOKEN", Pattern: `(?i)\b(?:ghp_|gho_|ghu_|ghs_|ghr_|github_pat_)[A-Za-z0-9_]{15,}\b`, Sample: "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ123456"},
		{Name: "AWS Access Key", Type: "AWS_KEY", Pattern: `\bAKIA[0-9A-Z]{16}\b`, Sample: "AKIAIOSFODNN7EXAMPLE"},
		{Name: "PEM 私钥", Type: "PEM_KEY", Pattern: `-----BEGIN [A-Z ]*PRIVATE KEY-----\s*[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----`, Sample: "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAx\n-----END RSA PRIVATE KEY-----"},
		{Name: "美国社会安全号", Type: "SSN_US", Pattern: `\b\d{3}-\d{2}-\d{4}\b`, Sample: "123-45-6789"},
	}
}

func newRuleStore() *ruleStore {
	s := &ruleStore{rules: defaultRules()}
	_ = s.compile()
	return s
}

// fillDefaultTypes 给 Type 为空的规则补默认类型标签（按名称匹配 defaultRules，否则 UNKNOWN）。
// 兼容旧版 rules.json（没有 type 字段）。
func (s *ruleStore) fillDefaultTypes() {
	def := map[string]string{}
	for _, r := range defaultRules() {
		if r.Type != "" {
			def[r.Name] = r.Type
		}
	}
	s.mu.Lock()
	for i := range s.rules {
		if strings.TrimSpace(s.rules[i].Type) == "" {
			if t, ok := def[s.rules[i].Name]; ok {
				s.rules[i].Type = t
			} else {
				s.rules[i].Type = TypeUnknown
			}
		}
	}
	s.mu.Unlock()
}

func (s *ruleStore) compile() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.rules {
		re, err := regexp.Compile(s.rules[i].Pattern)
		if err != nil {
			return err
		}
		s.rules[i].re = re
	}
	return nil
}

// all 返回规则副本（含编译好的 re）。
func (s *ruleStore) all() []Rule {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Rule, len(s.rules))
	copy(out, s.rules)
	return out
}

// add 添加规则，校验正则合法性。typ 为占位符类型标签（如 PHONE/IDCARD），空则 UNKNOWN。
func (s *ruleStore) add(name, pattern, sample, typ string) error {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return fmt.Errorf("正则不合法: %v", err)
	}
	t := strings.ToUpper(strings.TrimSpace(typ))
	if t == "" {
		t = TypeUnknown
	}
	s.mu.Lock()
	for i := range s.rules {
		if s.rules[i].Name == name {
			s.mu.Unlock()
			return fmt.Errorf("规则 %q 已存在", name)
		}
	}
	if strings.TrimSpace(name) == "" {
		s.mu.Unlock()
		return fmt.Errorf("规则名为空")
	}
	s.rules = append(s.rules, Rule{Name: name, Type: t, Pattern: pattern, Sample: sample, re: re})
	s.mu.Unlock()
	return s.save()
}

// update 按名称更新规则（可选改名 + 正则 + 示例 + 类型标签），并重新编译。
// newName 为空表示保持原名；若改名则校验新名不与其它规则冲突。
// typ 为空表示保持原类型标签；非空则更新占位符类型标签。
func (s *ruleStore) update(name, newName, pattern, sample, typ string) error {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return fmt.Errorf("正则不合法: %v", err)
	}
	// 注意：sync.RWMutex 不可重入，持写锁时不能调用需要读锁的 save()，
	// 必须先释放写锁再落盘，否则死锁（读锁请求会阻塞在未释放的写锁上）。
	final := strings.TrimSpace(newName)
	if final == "" {
		final = name
	}
	s.mu.Lock()
	found := false
	// 改名冲突检查：目标名若被其它规则占用则拒绝（改名前后同名允许）。
	if final != name {
		for i := range s.rules {
			if s.rules[i].Name == final {
				s.mu.Unlock()
				return fmt.Errorf("规则 %q 已存在", final)
			}
		}
	}
	for i := range s.rules {
		if s.rules[i].Name == name {
			s.rules[i].Name = final
			s.rules[i].Pattern = pattern
			s.rules[i].Sample = sample
			s.rules[i].re = re
			if t := strings.ToUpper(strings.TrimSpace(typ)); t != "" {
				s.rules[i].Type = t
			}
			found = true
			break
		}
	}
	s.mu.Unlock()
	if !found {
		return fmt.Errorf("规则 %q 不存在", name)
	}
	return s.save()
}

// remove 按名称删除规则。
func (s *ruleStore) remove(name string) error {
	s.mu.Lock()
	for i := range s.rules {
		if s.rules[i].Name == name {
			s.rules = append(s.rules[:i], s.rules[i+1:]...)
			s.mu.Unlock()
			return s.save()
		}
	}
	s.mu.Unlock()
	return fmt.Errorf("规则 %q 不存在", name)
}

// matches 判断某真实值是否命中任一规则（用于区分自动 vs 手动自定义）。
func (s *ruleStore) matches(real string) bool {
	for _, r := range s.all() {
		if r.re != nil && r.re.MatchString(real) {
			return true
		}
	}
	return false
}

// load 从文件加载规则；无文件则写入默认规则。
func (s *ruleStore) load() error {
	data, err := os.ReadFile(rulesFile)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if len(data) > 0 {
		var raw struct {
			Rules []Rule `json:"rules"`
		}
		if err := json.Unmarshal(data, &raw); err != nil {
			return err
		}
		if len(raw.Rules) > 0 {
			s.mu.Lock()
			s.rules = raw.Rules
			s.mu.Unlock()
			s.fillDefaultTypes() // 旧规则文件无 type 字段，这里补默认类型
		}
	}
	if err := s.compile(); err != nil {
		return err
	}
	if os.IsNotExist(err) {
		return s.save()
	}
	return nil
}

// save 原子落盘。
func (s *ruleStore) save() error {
	s.mu.RLock()
	data, err := json.Marshal(struct {
		Rules []Rule `json:"rules"`
	}{s.rules})
	s.mu.RUnlock()
	if err != nil {
		return err
	}
	tmp := rulesFile + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, rulesFile)
}
