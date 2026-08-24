package main

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
)

// 历史去重：相同输入文本不新增，只刷新时间与结果。
func TestSelfTestHistoryDedup(t *testing.T) {
	oldFile := selftestHistFile
	selftestHistFile = t.TempDir() + "/h.json"
	selftestHist = newSelftestHistory(100)
	defer func() { selftestHistFile = oldFile }()

	selftestHist.add(HistoryEntry{Text: "t1", Masked: "m", Restored: "r", Count: 1})
	selftestHist.add(HistoryEntry{Text: "t2", Masked: "m2", Restored: "r2", Count: 2})
	selftestHist.add(HistoryEntry{Text: "t1", Masked: "m1-new", Restored: "r1-new", Count: 9})

	list := selftestHist.list()
	if len(list) != 2 {
		t.Fatalf("去重后应为 2 条, got %d", len(list))
	}
	found := false
	for _, e := range list {
		if e.Text == "t1" {
			if e.Count != 9 || e.Masked != "m1-new" {
				t.Fatalf("t1 未刷新为最新结果: %+v", e)
			}
			found = true
		}
	}
	if !found {
		t.Fatalf("t1 应存在")
	}
}

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
