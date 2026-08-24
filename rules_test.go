package main

import (
	"testing"
)

// 用一个隔离的 ruleStore + 临时落盘文件，避免污染真实 rules.json。
func newTestRuleStore(t *testing.T) *ruleStore {
	t.Helper()
	old := rulesFile
	rulesFile = t.TempDir() + "/rules.json"
	t.Cleanup(func() { rulesFile = old })
	return newRuleStore()
}

func TestRuleStoreUpdate(t *testing.T) {
	s := newTestRuleStore(t)

	// 更新已存在的默认规则
	if err := s.update("中国大陆手机号", "", `1[3-9][0-9]{9}`, "13800000000", ""); err != nil {
		t.Fatalf("update: %v", err)
	}
	found := false
	for _, r := range s.all() {
		if r.Name == "中国大陆手机号" {
			found = true
			if r.Pattern != `1[3-9][0-9]{9}` || r.Sample != "13800000000" {
				t.Fatalf("not updated: %+v", r)
			}
			if r.re == nil || !r.re.MatchString("13800000000") {
				t.Fatalf("compiled regex not updated")
			}
		}
	}
	if !found {
		t.Fatalf("rule not found after update")
	}

	// 更新不存在的规则应报错
	if err := s.update("不存在的规则", "", `1`, "1", ""); err == nil {
		t.Fatalf("expected error updating nonexistent rule")
	}

	// 非法正则应报错
	if err := s.update("中国大陆手机号", "", `[`, `[`, ""); err == nil {
		t.Fatalf("expected error for invalid pattern")
	}
	// 非法更新失败后原规则保持不变
	for _, r := range s.all() {
		if r.Name == "中国大陆手机号" && r.Pattern != `1[3-9][0-9]{9}` {
			t.Fatalf("rule corrupted after failed update: %+v", r)
		}
	}
}

func TestRuleStoreRename(t *testing.T) {
	s := newTestRuleStore(t)

	// 改名为新名字
	if err := s.update("中国大陆手机号", "手机号", `1[3-9][0-9]{9}`, "13800000000", ""); err != nil {
		t.Fatalf("rename: %v", err)
	}
	foundNew := false
	for _, r := range s.all() {
		if r.Name == "手机号" {
			foundNew = true
		}
		if r.Name == "中国大陆手机号" {
			t.Fatalf("old name still exists after rename")
		}
	}
	if !foundNew {
		t.Fatalf("new name not found after rename")
	}

	// 改名为已存在的规则名应报错
	if err := s.update("手机号", "邮箱", `1[3-9][0-9]{9}`, "x", ""); err == nil {
		t.Fatalf("expected error renaming to existing name")
	}
	// 原名（改回）允许
	if err := s.update("手机号", "中国大陆手机号", `1[3-9][0-9]{9}`, "13800000000", ""); err != nil {
		t.Fatalf("rename back should be allowed: %v", err)
	}
}

func TestRuleStoreAddDuplicateAndInvalid(t *testing.T) {
	s := newTestRuleStore(t)

	// 添加合法规则
	if err := s.add("自定义", `\d{6}`, "123456", ""); err != nil {
		t.Fatalf("add: %v", err)
	}
	// 重复名称应报错
	if err := s.add("自定义", `\d{6}`, "654321", ""); err == nil {
		t.Fatalf("expected error for duplicate name")
	}
	// 非法正则应报错且不新增
	if err := s.add("坏规则", `(`, `(`, ""); err == nil {
		t.Fatalf("expected error for invalid pattern")
	}
	for _, r := range s.all() {
		if r.Name == "坏规则" {
			t.Fatalf("invalid rule should not be added")
		}
	}
}

func TestRuleStoreRemove(t *testing.T) {
	s := newTestRuleStore(t)
	if err := s.remove("中国大陆手机号"); err != nil {
		t.Fatalf("remove: %v", err)
	}
	for _, r := range s.all() {
		if r.Name == "中国大陆手机号" {
			t.Fatalf("rule should have been removed")
		}
	}
	// 删除不存在的应报错
	if err := s.remove("不存在"); err == nil {
		t.Fatalf("expected error removing nonexistent rule")
	}
}

// 占位符类型标签与规则绑定：add/update 时能设置/更新 type。
func TestRuleStoreType(t *testing.T) {
	s := newTestRuleStore(t)

	// 新增规则带类型标签
	if err := s.add("自定义六位码", `\d{6}`, "123456", "CODE"); err != nil {
		t.Fatalf("add: %v", err)
	}
	for _, r := range s.all() {
		if r.Name == "自定义六位码" {
			if r.Type != "CODE" {
				t.Fatalf("type should be CODE, got %q", r.Type)
			}
		}
	}

	// 新增规则 type 留空 -> UNKNOWN
	if err := s.add("无类型规则", `\d{3}`, "123", ""); err != nil {
		t.Fatalf("add: %v", err)
	}
	for _, r := range s.all() {
		if r.Name == "无类型规则" && r.Type != TypeUnknown {
			t.Fatalf("empty type should fallback to UNKNOWN, got %q", r.Type)
		}
	}

	// 更新规则时改类型
	if err := s.update("自定义六位码", "", `\d{6}`, "123456", "NewCode"); err != nil {
		t.Fatalf("update: %v", err)
	}
	for _, r := range s.all() {
		if r.Name == "自定义六位码" && r.Type != "NEWCODE" {
			t.Fatalf("type should be uppercased NEWCODE, got %q", r.Type)
		}
	}

	// 更新规则时 type 留空 -> 保持原类型
	if err := s.update("自定义六位码", "", `\d{6}`, "123456", ""); err != nil {
		t.Fatalf("update: %v", err)
	}
	for _, r := range s.all() {
		if r.Name == "自定义六位码" && r.Type != "NEWCODE" {
			t.Fatalf("empty type should keep existing type, got %q", r.Type)
		}
	}
}

// 所有内置规则应都能命中其示例，确保默认配置可用。
func TestDefaultRulesMatchSamples(t *testing.T) {
	s := newTestRuleStore(t)
	for _, r := range s.all() {
		if r.re == nil {
			t.Fatalf("rule %q has nil compiled regex", r.Name)
		}
		if r.Sample == "" {
			continue
		}
		if !r.re.MatchString(r.Sample) {
			t.Fatalf("rule %q (%s) does not match its sample %q", r.Name, r.Pattern, r.Sample)
		}
	}
}
