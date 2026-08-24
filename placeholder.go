package main

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// ---------------------------------------------------------------------------
// 占位符格式（可配置，默认 <<PII:{type}:{id}>>）
// ---------------------------------------------------------------------------
//
// 格式由三段组成：Prefix + type + Sep + id + Suffix。
// 例：<<PII:PHONE:1>>  ->  Prefix="<<PII:"  Sep=":"  Suffix=">>"
// type 是规则的类型标签（PHONE/IDCARD/...），手动添加的映射用 UNKNOWN。
// 可在后台配置，改动后需重启并建议清空旧映射（旧格式占位符不再匹配新正则）。
// 该结构更好看，且较 [[PID_n]] 更难被常规替换误伤。

type phFormat struct {
	Prefix string `json:"prefix"` // 如 <<PII:
	Sep    string `json:"sep"`    // 类型与编号间分隔符，如 :
	Suffix string `json:"suffix"` // 如 >>
}

// 占位符类型标签。
const TypeUnknown = "UNKNOWN"

var (
	phFmt         phFormat
	placeholderRe *regexp.Regexp // 识别完整占位符 <<PII:TYPE:ID>>
)

// initPhFormat 按配置构建占位符正则，返回错误（格式非法时）。
func initPhFormat(f phFormat) error {
	if f.Prefix == "" || f.Sep == "" || f.Suffix == "" {
		return fmt.Errorf("占位符格式的前缀/分隔符/后缀不能为空")
	}
	phFmt = f
	pat := regexp.QuoteMeta(f.Prefix) + "[A-Z0-9_]+" + regexp.QuoteMeta(f.Sep) + "[0-9]+" + regexp.QuoteMeta(f.Suffix)
	re, err := regexp.Compile(pat)
	if err != nil {
		return err
	}
	placeholderRe = re
	return nil
}

// 包初始化时给一个默认格式，保证测试与启动前 placeholderRe 已可用。
func init() {
	_ = initPhFormat(phFormat{Prefix: "<<PII:", Sep: ":", Suffix: ">>"})
}

// phFor 生成占位符，空类型兜底为 UNKNOWN。
func phFor(typ string, id uint64) string {
	if typ == "" {
		typ = TypeUnknown
	}
	return fmt.Sprintf("%s%s%s%d%s", phFmt.Prefix, typ, phFmt.Sep, id, phFmt.Suffix)
}

// phType 从占位符提取类型标签，异常返回 UNKNOWN。
func phType(ph string) string {
	if !strings.HasPrefix(ph, phFmt.Prefix) {
		return TypeUnknown
	}
	rest := strings.TrimPrefix(ph, phFmt.Prefix)
	if i := strings.Index(rest, phFmt.Sep); i >= 0 {
		return rest[:i]
	}
	return TypeUnknown
}

// phNumber 解析占位符里的编号 <<PII:PHONE:123>> -> 123。
func phNumber(ph string) int {
	if !strings.HasPrefix(ph, phFmt.Prefix) {
		return 0
	}
	rest := strings.TrimPrefix(ph, phFmt.Prefix)
	if i := strings.Index(rest, phFmt.Sep); i >= 0 {
		rest = rest[i+len(phFmt.Sep):]
		rest = strings.TrimSuffix(rest, phFmt.Suffix)
		n, _ := strconv.Atoi(rest)
		return n
	}
	return 0
}

// isTypeChars 判断是否为占位符类型标签的合法字符（大写字母/数字/下划线）。
func isTypeChars(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if !((c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_') {
			return false
		}
	}
	return true
}

// isDanglingPrefix 判断 t 是否为某个合法占位符的严格（未闭合）前缀。供 splitDangling 使用。
// 用字符串解析而非正则，更可控。
func isDanglingPrefix(t string) bool {
	if t == "" {
		return false
	}
	p, sep, suf := phFmt.Prefix, phFmt.Sep, phFmt.Suffix
	// 情况A：t 是 Prefix 的严格前缀（prefix 本身被拆）
	if len(t) < len(p) && strings.HasPrefix(p, t) {
		return true
	}
	// t 必须完整以 prefix 开头
	if !strings.HasPrefix(t, p) {
		return false
	}
	rest := t[len(p):]
	// 情况B：还没出现 sep —— rest 应为 type 前缀，或 sep 的部分前缀
	i := strings.Index(rest, sep)
	if i < 0 {
		if isTypeChars(rest) {
			return true // type 未闭合
		}
		return len(rest) < len(sep) && strings.HasPrefix(sep, rest) // sep 被拆
	}
	typePart := rest[:i]
	if typePart == "" || !isTypeChars(typePart) {
		return false
	}
	after := rest[i+len(sep):]
	j := 0
	for j < len(after) && after[j] >= '0' && after[j] <= '9' {
		j++
	}
	rem := after[j:]
	if rem == "" {
		return true // 数字部分，suffix 未开始
	}
	if rem == suf {
		return false // 完整闭合，非 dangling
	}
	// rem 是 suffix 的严格前缀（未闭合）
	return len(rem) < len(suf) && strings.HasPrefix(suf, rem)
}
