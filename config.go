package main

import (
	"encoding/json"
	"log"
	"os"
	"sync"
)

// appConfig 运行配置（管理面板可改，落盘持久化，供多用户/部署通用化）。
type appConfig struct {
	ForwardTarget string `json:"forward_target"` // 转发目标（热生效）
	ListenAddr    string `json:"listen_addr"`    // 代理监听端口（重启生效）
	AdminAddr     string `json:"admin_addr"`     // 管理面板端口（重启生效）
	StoreFile     string `json:"store_file"`     // 映射落盘文件
	RulesFile     string `json:"rules_file"`     // 规则落盘文件
}

// configStore 并发安全的配置存取。
type configStore struct {
	mu   sync.RWMutex
	path string
	c    appConfig
}

// appCfg 全局配置。config 文件路径可用 PII_CONFIG_FILE 覆盖。
var appCfg = &configStore{path: envOr("PII_CONFIG_FILE", "config.json")}

// load 读取配置：环境变量为默认，config 文件里非空项覆盖之。
func (s *configStore) load() {
	def := appConfig{
		ForwardTarget: envOr("PII_TARGET", "http://localhost:3000"),
		ListenAddr:    envOr("PII_LISTEN", ":3001"),
		AdminAddr:     envOr("PII_ADMIN", ":9090"),
		StoreFile:     envOr("PII_STORE_FILE", "pii-store.json"),
		RulesFile:     envOr("PII_RULES_FILE", "rules.json"),
	}
	s.mu.Lock()
	s.c = def
	if data, err := os.ReadFile(s.path); err == nil {
		var file appConfig
		if json.Unmarshal(data, &file) == nil {
			mergeNonEmpty(&s.c, &file)
		}
	} else if !os.IsNotExist(err) {
		log.Printf("read config %s: %v", s.path, err)
	}
	applyConfig(s.c)
	_ = s.persistLocked() // 落盘当前生效配置
	s.mu.Unlock()
}

func mergeNonEmpty(dst *appConfig, src *appConfig) {
	if src.ForwardTarget != "" {
		dst.ForwardTarget = src.ForwardTarget
	}
	if src.ListenAddr != "" {
		dst.ListenAddr = src.ListenAddr
	}
	if src.AdminAddr != "" {
		dst.AdminAddr = src.AdminAddr
	}
	if src.StoreFile != "" {
		dst.StoreFile = src.StoreFile
	}
	if src.RulesFile != "" {
		dst.RulesFile = src.RulesFile
	}
}

// applyConfig 把端口/文件类配置同步到全局变量（这些在启动时使用）。
func applyConfig(c appConfig) {
	listenAddr = c.ListenAddr
	adminAddr = c.AdminAddr
	piiStoreFile = c.StoreFile
	rulesFile = c.RulesFile
}

func (s *configStore) Target() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.c.ForwardTarget
}

func (s *configStore) Get() appConfig {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.c
}

// SetTarget 热更新转发目标并落盘（对后续请求立即生效）。
func (s *configStore) SetTarget(t string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.c.ForwardTarget = t
	return s.persistLocked()
}

// Save 整体保存配置（端口类改动需重启生效）。
func (s *configStore) Save(c appConfig) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.c = c
	applyConfig(c)
	return s.persistLocked()
}

// persistLocked 原子落盘（调用方需已持锁）。
func (s *configStore) persistLocked() error {
	data, err := json.MarshalIndent(s.c, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}
