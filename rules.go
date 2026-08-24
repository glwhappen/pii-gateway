package main

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sync"
)

// Rule 一条脱敏正则规则。
type Rule struct {
	Name    string         `json:"name"`
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
		{Name: "银行卡号", Pattern: `(?:62\d{14,17}|4\d{15}|5[1-5]\d{14})`, Sample: "6222021234567890123"},
		{Name: "中国大陆身份证", Pattern: `(?i)[0-9]{17}[0-9X]`, Sample: "110101199003071234"},
		{Name: "中国大陆手机号", Pattern: `1[3-9][0-9]{9}`, Sample: "13812345678"},
		{Name: "邮箱", Pattern: `[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}`, Sample: "abc@test.com"},
		{Name: "中国大陆车牌", Pattern: `[京津沪渝冀豫云辽黑湘皖鲁新苏浙赣鄂桂甘晋蒙陕吉闽贵粤青藏川宁琼使领][A-HJ-NP-Z][A-HJ-NP-Z0-9]{5,6}`, Sample: "粤B12345"},
		{Name: "固定电话", Pattern: `0\d{2,3}-?\d{7,8}`, Sample: "0755-12345678"},
		{Name: "中国护照", Pattern: `(?i)[eghpsd]\d{8}`, Sample: "E12345678"},
	}
}

func newRuleStore() *ruleStore {
	s := &ruleStore{rules: defaultRules()}
	_ = s.compile()
	return s
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

// add 添加规则，校验正则合法性。
func (s *ruleStore) add(name, pattern, sample string) error {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return fmt.Errorf("正则不合法: %v", err)
	}
	s.mu.Lock()
	for i := range s.rules {
		if s.rules[i].Name == name {
			s.mu.Unlock()
			return fmt.Errorf("规则 %q 已存在", name)
		}
	}
	s.rules = append(s.rules, Rule{Name: name, Pattern: pattern, Sample: sample, re: re})
	s.mu.Unlock()
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
