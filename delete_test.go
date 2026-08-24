package main

import (
	"strings"
	"testing"
)

// 映射删除：按占位符删除单条，真实值不再脱敏，且删除后重新进入脱敏流程。
func TestDeleteMapping(t *testing.T) {
	clean := withTmpStore(t)
	defer clean()

	globalStore.remember("13800138000", "<<PII:PHONE:1>>")

	// 删除前：应被脱敏成原占位符
	m1 := newMapping()
	out1 := string(mask([]byte("手机13800138000"), m1))
	if !strings.Contains(out1, "<<PII:PHONE:1>>") {
		t.Fatalf("删除前应脱敏: %s", out1)
	}

	// 删除：返回真实值
	real, ok := globalStore.delete("<<PII:PHONE:1>>")
	if !ok || real != "13800138000" {
		t.Fatalf("delete 应返回真实值, got %q, %v", real, ok)
	}
	if globalStore.size() != 0 {
		t.Fatalf("删除后 size 应为 0, got %d", globalStore.size())
	}
	if _, ok := globalStore.lookup("13800138000"); ok {
		t.Fatalf("删除后不应再查到该真实值")
	}

	// 删除后：同一真实值再次出现，重新被规则脱敏为新占位符（不再复用旧占位符）
	m2 := newMapping()
	out2 := string(mask([]byte("手机13800138000"), m2))
	if strings.Contains(out2, "13800138000") {
		t.Fatalf("删除后应重新脱敏, 残留明文: %s", out2)
	}
	if strings.Contains(out2, "<<PII:PHONE:1>>") {
		t.Fatalf("删除后不应再使用旧占位符: %s", out2)
	}
	if !strings.Contains(out2, "<<PII:PHONE:") {
		t.Fatalf("删除后应重新分配新占位符: %s", out2)
	}
	// 且 store 中重新建立了该真实值的映射
	if _, ok := globalStore.lookup("13800138000"); !ok {
		t.Fatalf("删除后再次脱敏应重新建立映射")
	}
}

// 删除不存在的占位符应返回 ok=false。
func TestDeleteUnknownPlaceholder(t *testing.T) {
	clean := withTmpStore(t)
	defer clean()

	if _, ok := globalStore.delete("<<PII:PHONE:999>>"); ok {
		t.Fatalf("删除不存在的占位符应返回 ok=false")
	}
}

// 删除应同时清除该真实值的忽略状态。
func TestDeleteClearsIgnored(t *testing.T) {
	clean := withTmpStore(t)
	defer clean()

	globalStore.remember("李小明", "<<PII:NAME:1>>")
	if err := globalStore.setIgnored("<<PII:NAME:1>>", true); err != nil {
		t.Fatalf("setIgnored: %v", err)
	}
	if _, ok := globalStore.delete("<<PII:NAME:1>>"); !ok {
		t.Fatalf("delete 应成功")
	}
	if globalStore.isIgnored("李小明") {
		t.Fatalf("删除后应清除忽略状态")
	}
}
