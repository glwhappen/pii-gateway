package main

import (
	"strings"
	"testing"
)

// 用一个隔离的 piiStoreFile，避免测试写入真实 pii-store.json。
func withTmpStore(t *testing.T) func() {
	t.Helper()
	old := piiStoreFile
	piiStoreFile = t.TempDir() + "/store.json"
	ResetPIIStore()
	return func() { piiStoreFile = old }
}

func TestNamesMask(t *testing.T) {
	clean := withTmpStore(t)
	defer clean()
	oldNames := namesList
	defer func() { namesList = oldNames }()
	namesList = []string{"张三", "李四"}

	m := newMapping()
	masked := mask([]byte("我叫张三，我对象叫李四，电话13812345678"), m)
	s := string(masked)
	if strings.Contains(s, "张三") || strings.Contains(s, "李四") {
		t.Fatalf("名单名字未被掩码: %s", s)
	}
	if !strings.Contains(s, "<<PII:NAME:") {
		t.Fatalf("未生成 NAME 占位符: %s", s)
	}
	restored := string(restore(masked, m))
	if !strings.Contains(restored, "张三") || !strings.Contains(restored, "李四") {
		t.Fatalf("还原失败: %s", restored)
	}
}

// 长名优先：名单中较长的词不应被较短词先替换而拆碎。
func TestNamesLongerFirst(t *testing.T) {
	clean := withTmpStore(t)
	defer clean()
	oldNames := namesList
	defer func() { namesList = oldNames }()
	namesList = []string{"李明", "李明轩"}

	m := newMapping()
	masked := mask([]byte("李明轩今天去上学"), m)
	s := string(masked)
	// 整个「李明轩」应被替换，不应残留「轩」
	if strings.Contains(s, "李明") {
		t.Fatalf("长名被拆碎: %s", s)
	}
	restored := string(restore(masked, m))
	if restored != "李明轩今天去上学" {
		t.Fatalf("还原不完整: %q", restored)
	}
}

// 名单为空时不进行任何掩码。
func TestNamesEmpty(t *testing.T) {
	clean := withTmpStore(t)
	defer clean()
	oldNames := namesList
	defer func() { namesList = oldNames }()
	namesList = nil

	m := newMapping()
	masked := mask([]byte("我叫张三"), m)
	if string(masked) != "我叫张三" {
		t.Fatalf("空名单不应掩码: %s", masked)
	}
}
