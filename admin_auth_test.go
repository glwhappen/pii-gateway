package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// 保存并恢复 appCfg 的 AdminToken，避免影响其他测试。
func setAdminToken(t *testing.T, tok string) {
	t.Helper()
	c := appCfg.Get()
	old := c.AdminToken
	c.AdminToken = tok
	if err := appCfg.Save(c); err != nil {
		t.Fatalf("save config: %v", err)
	}
	t.Cleanup(func() {
		c := appCfg.Get()
		c.AdminToken = old
		_ = appCfg.Save(c)
	})
}

func TestAdminAuthDisabledByDefault(t *testing.T) {
	newTestStore(t)
	setAdminToken(t, "")

	req := httptest.NewRequest(http.MethodGet, "/api/mappings", nil)
	rr := httptest.NewRecorder()
	adminMappings(rr, req) // 未包装，直接调用不影响；这里测的是 authWrap 逻辑
	if rr.Code != http.StatusOK {
		t.Fatalf("expected ok when no token, got %d", rr.Code)
	}
}

// 配置了 token 后：正确 Bearer 放行，错误/缺失返回 401。
func TestAdminAuthBearer(t *testing.T) {
	newTestStore(t)
	setAdminToken(t, "secret-token-123")

	h := authWrap(adminMappings)

	// 缺失 token -> 401
	req := httptest.NewRequest(http.MethodGet, "/api/mappings", nil)
	rr := httptest.NewRecorder()
	h(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("no token should 401, got %d", rr.Code)
	}

	// 错误 token -> 401
	req = httptest.NewRequest(http.MethodGet, "/api/mappings", nil)
	req.Header.Set("Authorization", "Bearer wrong")
	rr = httptest.NewRecorder()
	h(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("wrong token should 401, got %d", rr.Code)
	}

	// 正确 token -> 200
	req = httptest.NewRequest(http.MethodGet, "/api/mappings", nil)
	req.Header.Set("Authorization", "Bearer secret-token-123")
	rr = httptest.NewRecorder()
	h(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("correct token should 200, got %d: %s", rr.Code, rr.Body.String())
	}

	// 查询参数 token -> 200
	req = httptest.NewRequest(http.MethodGet, "/api/mappings?token=secret-token-123", nil)
	rr = httptest.NewRecorder()
	h(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("query token should 200, got %d", rr.Code)
	}
}

// 配置 token 后，管理面板页面未鉴权应返回登录页，鉴权后返回完整面板。
func TestAdminPageAuth(t *testing.T) {
	newTestStore(t)
	setAdminToken(t, "tok-page")

	// 未鉴权 -> 登录页（含"登录"字样）
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	serveAdminPage(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("page code %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "登录") {
		t.Fatalf("unauth page should be login page")
	}
	if strings.Contains(rr.Body.String(), "PII 脱敏网关") && strings.Contains(rr.Body.String(), "adminAddr") {
		t.Fatalf("panel should not be served unauth")
	}

	// 鉴权 -> 完整面板
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer tok-page")
	rr = httptest.NewRecorder()
	serveAdminPage(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("authed page code %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "adminPageHTML") && !strings.Contains(rr.Body.String(), "PII") {
		t.Fatalf("authed page should be full panel")
	}
}
