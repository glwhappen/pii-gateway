package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestInjectSystemHint(t *testing.T) {
	oldHint, oldOn := systemHint, systemHintEnabled
	defer func() { systemHint, systemHintEnabled = oldHint, oldOn }()
	systemHint = "请严格保留 <<PII:...>> 占位符"
	systemHintEnabled = true

	// 开关关闭时不注入（即使有文字），文字保留
	systemHintEnabled = false
	if !jsonEqual(injectSystemHint([]byte(`{"messages":[{"role":"user","content":"hi"}]}`)), []byte(`{"messages":[{"role":"user","content":"hi"}]}`)) {
		t.Fatalf("开关关闭时应原样返回")
	}
	systemHintEnabled = true

	// 正常 chat 请求：应在 messages 最前插入 system 说明
	body := []byte(`{"model":"x","messages":[{"role":"user","content":"我的电话是13812345678"}],"temperature":0.7}`)
	out := injectSystemHint(body)
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(out, &obj); err != nil {
		t.Fatalf("注入后不是合法 JSON: %v", err)
	}
	var msgs []map[string]string
	if err := json.Unmarshal(obj["messages"], &msgs); err != nil {
		t.Fatalf("解析 messages 失败: %v", err)
	}
	if len(msgs) != 2 {
		t.Fatalf("应插入后共 2 条消息, 实际 %d", len(msgs))
	}
	if msgs[0]["role"] != "system" || msgs[0]["content"] != systemHint {
		t.Fatalf("首条应为注入的 system 说明: %+v", msgs[0])
	}
	if msgs[1]["role"] != "user" || !strings.Contains(msgs[1]["content"], "13812345678") {
		t.Fatalf("原 user 消息应保留且未被打乱: %+v", msgs[1])
	}
	// 顶层其他字段应保留（temperature=0.7）
	if !strings.Contains(string(obj["temperature"]), "0.7") {
		t.Fatalf("顶层 temperature 字段应保留: %s", obj["temperature"])
	}

	// system_hint 为空时不注入
	systemHint = ""
	if !jsonEqual(injectSystemHint(body), body) {
		t.Fatalf("system_hint 为空时应原样返回")
	}

	// 非 JSON body 不注入
	systemHint = "x"
	if !jsonEqual(injectSystemHint([]byte("not json")), []byte("not json")) {
		t.Fatalf("非 JSON body 应原样返回")
	}
}

func jsonEqual(a, b []byte) bool {
	var x, y any
	if json.Unmarshal(a, &x) != nil || json.Unmarshal(b, &y) != nil {
		return string(a) == string(b)
	}
	xa, _ := json.Marshal(x)
	yb, _ := json.Marshal(y)
	return string(xa) == string(yb)
}
