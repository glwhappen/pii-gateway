package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func mustEnc(t *testing.T, s string) string {
	t.Helper()
	e, err := mapEncrypt(s)
	if err != nil {
		t.Fatalf("encrypt %q: %v", s, err)
	}
	return e
}

// 用隔离的 store 落盘路径，避免污染真实 pii-store.json。
func newTestStore(t *testing.T) {
	t.Helper()
	old := piiStoreFile
	piiStoreFile = t.TempDir() + "/store.json"
	t.Cleanup(func() { piiStoreFile = old })
	ResetPIIStore()
}

// POST 添加映射：请求里的 real 是密文，后端解密后以明文存储。
func TestAdminMappingsAddDecrypts(t *testing.T) {
	newTestStore(t)

	enc := mustEnc(t, "13911112222")
	req := httptest.NewRequest(http.MethodPost, "/api/mappings", strings.NewReader(`{"real":"`+enc+`"}`))
	rr := httptest.NewRecorder()
	adminMappingsAdd(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("add code %d: %s", rr.Code, rr.Body.String())
	}

	// 存储的必须是明文（脱敏引擎需要）
	if _, ok := globalStore.lookup("13911112222"); !ok {
		t.Fatalf("plaintext not stored in mapping store")
	}
}

// GET 返回映射表：real 必须是密文，且用前端密钥解密后得到明文。
func TestAdminMappingsReturnsEncrypted(t *testing.T) {
	newTestStore(t)

	// 先塞一条
	globalStore.remember("13911112222", "<<PII:UNKNOWN:1>>")
	if _, ok := globalStore.lookup("13911112222"); !ok {
		t.Fatalf("seed mapping failed")
	}

	req := httptest.NewRequest(http.MethodGet, "/api/mappings", nil)
	rr := httptest.NewRecorder()
	adminMappings(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("get code %d: %s", rr.Code, rr.Body.String())
	}

	var resp struct {
		Entries []struct {
			Placeholder string `json:"placeholder"`
			Real        string `json:"real"`
		} `json:"entries"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Entries) == 0 {
		t.Fatalf("no entries returned")
	}
	for _, e := range resp.Entries {
		// 密文绝不能是明文本身
		if strings.Contains(e.Real, "13911112222") {
			t.Fatalf("plaintext leaked into response: %s", e.Real)
		}
		dec, err := mapDecrypt(e.Real)
		if err != nil {
			t.Fatalf("decrypt %q: %v", e.Real, err)
		}
		if dec != "13911112222" {
			t.Fatalf("decrypted %q != expected", dec)
		}
	}
}

// 映射表加密往返：同一个明文加密两次得到不同密文（随机 IV），但都能解密回原文。
func TestAdminMappingsIVRandomness(t *testing.T) {
	newTestStore(t)
	a := mustEnc(t, "13800001111")
	b := mustEnc(t, "13800001111")
	if a == b {
		t.Fatalf("same plaintext produced identical ciphertext (IV not random)")
	}
	da, _ := mapDecrypt(a)
	db, _ := mapDecrypt(b)
	if da != "13800001111" || db != "13800001111" {
		t.Fatalf("round-trip mismatch: %q %q", da, db)
	}
}
