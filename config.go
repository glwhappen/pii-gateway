package main

import (
	"encoding/json"
	"log"
	"os"
	"strings"
	"sync"
)

// defaultSystemHint 默认注入给上游模型的说明，提醒其严格保留占位符，提升还原稳定性。
const defaultSystemHint = "请严格原样保留所有形如 <<PII:...>> 的占位符：不得翻译、改写、增删字符、改变大小写、添加/删除空格、拆分或合并。输出中必须与输入完全一致。"

// systemHint 全局生效的注入说明（由 appCfg / applyConfig 在启动或保存配置时设置，可热生效）。
var systemHint = defaultSystemHint

// systemHintEnabled 是否注入说明（默认关闭；关闭时即使 systemHint 有文字也不注入，但保留文字）。
var systemHintEnabled = false

// namesList 敏感名单（姓名等），正文出现即掩码。由 applyConfig 设置，可热生效。
var namesList []string

// onOffToBool 把 "on"/"1"/"true" 等解析为布尔，无法识别时返回 def。
func onOffToBool(s string, def bool) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "1", "true", "on", "yes", "y":
		return true
	case "0", "false", "off", "no", "n":
		return false
	default:
		return def
	}
}

// appConfig 运行配置（管理面板可改，落盘持久化，供多用户/部署通用化）。
type appConfig struct {
	ForwardTarget     string `json:"forward_target"`     // 转发目标（热生效）
	ListenAddr        string `json:"listen_addr"`        // 代理监听端口（重启生效）
	AdminAddr         string `json:"admin_addr"`         // 管理面板端口（重启生效）
	StoreFile         string `json:"store_file"`         // 映射落盘文件
	RulesFile         string `json:"rules_file"`         // 规则落盘文件
	PlaceholderPrefix string `json:"placeholder_prefix"` // 占位符前缀（重启生效，改后需清空旧映射）
	PlaceholderSep    string `json:"placeholder_sep"`    // 占位符类型/编号分隔符
	PlaceholderSuffix string `json:"placeholder_suffix"` // 占位符后缀
	SystemHint        string `json:"system_hint"`        // 注入给上游模型的说明（提醒保留占位符），可热生效
	SystemHintEnabled string `json:"system_hint_enabled"` // 是否注入说明："on"/"off"，空用默认(关闭)
	Names             []string `json:"names"`            // 敏感名单（姓名等），正文出现即掩码，可热生效
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
		ForwardTarget:     envOr("PII_TARGET", "http://localhost:3000"),
		ListenAddr:        envOr("PII_LISTEN", ":3001"),
		AdminAddr:         envOr("PII_ADMIN", ":9090"),
		StoreFile:         envOr("PII_STORE_FILE", "pii-store.json"),
		RulesFile:         envOr("PII_RULES_FILE", "rules.json"),
		PlaceholderPrefix: envOr("PII_PH_PREFIX", "<<PII:"),
		PlaceholderSep:    envOr("PII_PH_SEP", ":"),
		PlaceholderSuffix: envOr("PII_PH_SUFFIX", ">>"),
		SystemHint:        envOr("PII_SYSTEM_HINT", defaultSystemHint),
		SystemHintEnabled: envOr("PII_SYSTEM_HINT_ENABLED", "off"),
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
	if src.PlaceholderPrefix != "" {
		dst.PlaceholderPrefix = src.PlaceholderPrefix
	}
	if src.PlaceholderSep != "" {
		dst.PlaceholderSep = src.PlaceholderSep
	}
	if src.PlaceholderSuffix != "" {
		dst.PlaceholderSuffix = src.PlaceholderSuffix
	}
	if src.SystemHint != "" {
		dst.SystemHint = src.SystemHint
	}
	if src.SystemHintEnabled != "" {
		dst.SystemHintEnabled = src.SystemHintEnabled
	}
	if src.Names != nil { // 名单：空数组与未设置可区分
		dst.Names = src.Names
	}
}

// applyConfig 把端口/文件类配置同步到全局变量（这些在启动时使用）。
func applyConfig(c appConfig) {
	listenAddr = c.ListenAddr
	adminAddr = c.AdminAddr
	piiStoreFile = c.StoreFile
	rulesFile = c.RulesFile
	systemHint = c.SystemHint
	systemHintEnabled = onOffToBool(c.SystemHintEnabled, false)
	namesList = c.Names
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
