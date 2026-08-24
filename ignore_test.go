package main

import (
	"strings"
	"testing"
)

// 映射忽略：忽略后该真实值不再脱敏（保留明文），可取消恢复。
func TestIgnoreMapping(t *testing.T) {
	clean := withTmpStore(t)
	defer clean()

	globalStore.remember("13812345678", "<<PII:PHONE:1>>")

	// 未忽略：应被脱敏
	m1 := newMapping()
	if out := string(mask([]byte("手机13812345678"), m1)); strings.Contains(out, "13812345678") {
		t.Fatalf("未忽略时应脱敏: %s", out)
	}

	// 忽略后：不再脱敏，保留明文
	if err := globalStore.setIgnored("<<PII:PHONE:1>>", true); err != nil {
		t.Fatalf("setIgnored: %v", err)
	}
	if !globalStore.isIgnored("13812345678") {
		t.Fatalf("isIgnored 应为 true")
	}
	m2 := newMapping()
	if out := string(mask([]byte("手机13812345678"), m2)); !strings.Contains(out, "13812345678") {
		t.Fatalf("忽略后仍被脱敏: %s", out)
	}

	// 取消忽略：恢复脱敏
	if err := globalStore.setIgnored("<<PII:PHONE:1>>", false); err != nil {
		t.Fatalf("取消忽略: %v", err)
	}
	m3 := newMapping()
	if out := string(mask([]byte("手机13812345678"), m3)); strings.Contains(out, "13812345678") {
		t.Fatalf("取消忽略后应恢复脱敏: %s", out)
	}
}

// 忽略不存在的占位符应报错。
func TestIgnoreUnknownPlaceholder(t *testing.T) {
	clean := withTmpStore(t)
	defer clean()
	if err := globalStore.setIgnored("<<PII:PHONE:999>>", true); err == nil {
		t.Fatalf("忽略不存在的占位符应报错")
	}
}
