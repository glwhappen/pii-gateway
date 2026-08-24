package main

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
)

// 自测：加密传输往返 + 历史服务端落盘。
func TestSelfTestHistoryEncrypted(t *testing.T) {
	oldFile := selftestHistFile
	selftestHistFile = t.TempDir() + "/hist.json"
	selftestHist = newSelftestHistory(100)
	defer func() { selftestHistFile = oldFile }()

	// 前端用 mapEncrypt 加密输入发送
	encText, _ := mapEncrypt("手机13812345678")
	req := httptest.NewRequest("POST", "/api/self-test", strings.NewReader(fmt.Sprintf(`{"text":%q}`, encText)))
	w := httptest.NewRecorder()
	adminSelfTest(w, req)
	if w.Code != 200 {
		t.Fatalf("code=%d body=%s", w.Code, w.Body.String())
	}
	var resp struct {
		Masked   string `json:"masked"`
		Restored string `json:"restored"`
		Count    int    `json:"count"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	masked, _ := mapDecrypt(resp.Masked)
	restored, _ := mapDecrypt(resp.Restored)
	if strings.Contains(masked, "13812345678") {
		t.Fatalf("masked 响应含明文: %s", masked)
	}
	if !strings.Contains(restored, "13812345678") {
		t.Fatalf("restored 未还原: %s", restored)
	}

	// 历史已服务端保存
	list := selftestHist.list()
	if len(list) != 1 {
		t.Fatalf("历史应为 1 条, got %d", len(list))
	}
	if list[0].Text != "手机13812345678" {
		t.Fatalf("历史 Text 错误: %q", list[0].Text)
	}

	// 历史接口返回加密字段，可解密
	req2 := httptest.NewRequest("GET", "/api/self-test/history", nil)
	w2 := httptest.NewRecorder()
	adminSelftestHistory(w2, req2)
	var hist struct {
		Entries []map[string]any `json:"entries"`
	}
	if err := json.Unmarshal(w2.Body.Bytes(), &hist); err != nil {
		t.Fatalf("hist unmarshal: %v", err)
	}
	if len(hist.Entries) != 1 {
		t.Fatalf("history entries 应为 1, got %d", len(hist.Entries))
	}
	decText, err := mapDecrypt(hist.Entries[0]["text"].(string))
	if err != nil || decText != "手机13812345678" {
		t.Fatalf("历史 text 解密失败: %q err=%v", decText, err)
	}
}
