package main

import (
	"strings"
	"testing"
)

// 跨请求还原：真实 pi 会话中，"明文来源"(请求A读 USER.md)与"占位符输出"(请求B模型回答)
// 是两次独立 HTTP 请求。请求B 的 body 里只有占位符、没有明文，本次请求的 m.real 为空，
// 因此还原必须回退查全局持久映射(ph2real)，否则占位符无法还原。
func TestRestoreFallbackGlobalStore(t *testing.T) {
	clean := withTmpStore(t)
	defer clean()

	// 模拟"郭力玮"已在全局 store（请求A脱敏时 remember 的持久映射）
	globalStore.remember("郭力玮", "<<PII:NAME:31>>")

	// 请求B：body 里只有占位符，没有明文「郭力玮」，因此本次请求 mapping 为空
	m := newMapping()
	mask([]byte(`{"messages":[{"role":"assistant","content":"你的名字是 <<PII:NAME:31>>"}]}`), m)
	if m.MaskedCount() != 0 {
		t.Fatalf("请求B body 无明文，脱敏数应为 0，got %d", m.MaskedCount())
	}

	// 模型基于占位符输出；还原时应回退全局 store 还原成「郭力玮」
	restored := string(restore([]byte(`{"content":"你的名字是 <<PII:NAME:31>>"}`), m))
	if !strings.Contains(restored, "郭力玮") {
		t.Fatalf("兜底还原失败，未出现真实名字: %s", restored)
	}
	if strings.Contains(restored, "<<PII:NAME:31>>") {
		t.Fatalf("兜底还原后仍残留占位符: %s", restored)
	}
	if m.Restored == 0 {
		t.Fatalf("restore 应统计到还原次数")
	}
}

// 端到端复现真实 pi 会话：请求A 读到明文「郭力玮」(USER.md) 并脱敏建持久映射；
// 请求B 是模型最终回答，body 只有占位符。修复前请求B 还原失败(占位符残留)，
// 修复后应回退全局 store 还原成「郭力玮」。
func TestRestoreFallbackEndToEnd(t *testing.T) {
	clean := withTmpStore(t)
	defer clean()

	real := "郭力玮"

	// 请求A 之前，全局 store 已存在「郭力玮」映射(如同真实会话中该名字之前被脱敏过)
	globalStore.remember(real, "<<PII:NAME:31>>")

	// 请求A：读 USER.md，body 含明文「郭力玮」→ 脱敏成 <<PII:NAME:31>> 并 remember 到全局
	m1 := newMapping()
	masked1 := mask([]byte(`{"content":"* **姓名：** `+real+`"}`), m1)
	if m1.MaskedCount() != 1 {
		t.Fatalf("请求A 应脱敏 1 处, got %d", m1.MaskedCount())
	}
	if !strings.Contains(string(masked1), "<<PII:NAME:31>>") {
		t.Fatalf("请求A 应生成 NAME 占位符: %s", masked1)
	}

	// 请求B：模型最终回答，body 只有占位符(无明文)，本次 mapping 为空
	m2 := newMapping()
	resp := []byte(`{"content":"你的名字是 <<PII:NAME:31>>"}`)
	restored := string(restore(resp, m2))
	if !strings.Contains(restored, "郭力玮") {
		t.Fatalf("跨请求还原失败, 占位符未还原: %s", restored)
	}
	if strings.Contains(restored, "<<PII:NAME:31>>") {
		t.Fatalf("还原后仍残留占位符: %s", restored)
	}
}

// 兜底不误伤：本次请求 mapping 与全局 store 都没有的占位符，还原应原样保留。
func TestRestoreFallbackUnknownKeepsPlaceholder(t *testing.T) {
	clean := withTmpStore(t)
	defer clean()

	m := newMapping()
	// 构造一个只有占位符、既不在 m.real 也不在 globalStore 的响应
	resp := []byte(`{"content":"未知占位符 <<PII:NAME:999>>"}`)
	restored := string(restore(resp, m))
	if !strings.Contains(restored, "<<PII:NAME:999>>") {
		t.Fatalf("未知占位符应原样保留: %s", restored)
	}
}

// 本次请求映射优先：若本次请求 m.real 里有映射，优先用它（通常与全局一致，但保证局部优先）。
func TestRestoreFallbackRequestMappingWins(t *testing.T) {
	clean := withTmpStore(t)
	defer clean()

	// 全局 store 里该占位符对应「郭力玮」
	globalStore.remember("郭力玮", "<<PII:NAME:31>>")

	// 本次请求 m.real 手动塞一个不同映射，验证优先用 m.real
	m := newMapping()
	m.real["<<PII:NAME:31>>"] = "本次请求值"
	restored := string(restore([]byte(`{"content":"<<PII:NAME:31>>"}`), m))
	if !strings.Contains(restored, "本次请求值") {
		t.Fatalf("应优先用本次请求映射: %s", restored)
	}
	if strings.Contains(restored, "郭力玮") {
		t.Fatalf("不应回退全局映射覆盖本次请求映射: %s", restored)
	}
}
