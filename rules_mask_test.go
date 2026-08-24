package main

import (
	"strings"
	"testing"
)

// 每种内置规则单独出现的完整往返（脱敏->还原），确认各自工作。
func TestMaskSinglePIIRoundTrip(t *testing.T) {
	cases := []struct{ name, pii string }{
		{"银行卡号", "6222021234567890123"}, // 62 开头 19 位
		{"中国大陆身份证", "110101199003071234"},
		{"中国大陆手机号", "13812345678"},
		{"邮箱", "user@example.com"},
		{"中国大陆车牌", "粤B12345"},
		{"固定电话", "0755-12345678"},
		{"中国护照", "E12345678"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ResetPIIStore()
			text := "客户信息：" + tc.pii + " 请保密"
			m := newMapping()
			masked := mask([]byte(text), m)
			if strings.Contains(string(masked), tc.pii) {
				t.Fatalf("PII not masked: %s", masked)
			}
			if !strings.Contains(string(masked), "<<PII:") {
				t.Fatalf("no placeholder produced: %s", masked)
			}
			restored := restore(masked, m)
			if string(restored) != text {
				t.Fatalf("roundtrip mismatch:\n got: %s\nwant: %s", restored, text)
			}
			if strings.Contains(string(restored), "<<PII:") {
				t.Fatalf("placeholder leaked: %s", restored)
			}
		})
	}
}

// 所有类型的 PII 混在同一段文本里，一次性脱敏->还原。
// 验证：全部脱敏、占位符数==PII 数、还原后原文逐字一致、无残留。
func TestMaskCombinedText(t *testing.T) {
	ResetPIIStore()
	text := "客户张三，手机13812345678，身份证110101199003071234，邮箱user@example.com，" +
		"车牌粤B12345，座机0755-12345678，护照E12345678，银行卡6222021234567890123。"
	allPII := []string{
		"13812345678", "110101199003071234", "user@example.com",
		"粤B12345", "0755-12345678", "E12345678", "6222021234567890123",
	}
	m := newMapping()
	masked := mask([]byte(text), m)
	ms := string(masked)

	// 所有明文 PII 都不应再出现
	for _, p := range allPII {
		if strings.Contains(ms, p) {
			t.Fatalf("PII not masked (%s): %s", p, ms)
		}
	}
	// 占位符数 == PII 数（去重后每个 PII 一个占位符）
	if n := len(placeholderRe.FindAllString(ms, -1)); n != len(allPII) {
		t.Fatalf("expected %d placeholders, got %d: %s", len(allPII), n, ms)
	}

	// 完整还原，逐字一致
	restored := restore(masked, m)
	if string(restored) != text {
		t.Fatalf("combined roundtrip mismatch:\n got: %s\nwant: %s", restored, text)
	}
	if strings.Contains(string(restored), "<<PII:") {
		t.Fatalf("placeholder leaked: %s", restored)
	}
}

// 19 位银行卡不应被后续身份证规则截断（银行卡规则在前，先整体替换）。
// 这是笔记里强调的重叠正则坑，此处验证顺序保护有效。
func TestMaskBankCardNotTruncated(t *testing.T) {
	ResetPIIStore()
	card := "6222021234567890123" // 62 开头 19 位，身份证规则本会匹配其中 18 位
	text := "卡号：" + card + " 请核对"
	m := newMapping()
	masked := mask([]byte(text), m)
	ms := string(masked)
	if strings.Contains(ms, card) {
		t.Fatalf("bank card not masked: %s", ms)
	}
	// 必须整体脱敏为单个占位符，而非被截断成多个
	if n := len(placeholderRe.FindAllString(ms, -1)); n != 1 {
		t.Fatalf("bank card should be one placeholder, got %d: %s", n, ms)
	}
	restored := restore(masked, m)
	if !strings.Contains(string(restored), card) {
		t.Fatalf("bank card not fully restored: %s", restored)
	}
	if strings.Contains(string(restored), "<<PII:") {
		t.Fatalf("leak: %s", restored)
	}
}

// 手机号与座机同时出现：两者互不干扰，各自独立脱敏还原。
func TestMaskMobileAndLandline(t *testing.T) {
	ResetPIIStore()
	text := "手机13812345678，座机0755-12345678，请回电。"
	m := newMapping()
	masked := mask([]byte(text), m)
	ms := string(masked)
	for _, p := range []string{"13812345678", "0755-12345678"} {
		if strings.Contains(ms, p) {
			t.Fatalf("PII not masked (%s): %s", p, ms)
		}
	}
	restored := restore(masked, m)
	if string(restored) != text {
		t.Fatalf("roundtrip mismatch:\n got: %s\nwant: %s", restored, text)
	}
}

// 手动映射存在包含/前缀关系（如 1234 含 123）时，必须长值优先、确定性处理，
// 不能把长值拆开残留明文，也不能依赖 map 随机迭代顺序。
func TestManualEntrySubstringMapping(t *testing.T) {
	ResetPIIStore()
	// 手动添加两个互相包含的映射：1234（长）和 123（短）
	globalStore.remember("1234", "<<PII:UNKNOWN:1>>")
	globalStore.remember("123", "<<PII:UNKNOWN:2>>")

	text := "号码1234单独123结束" // 1234 是长串，123 独立出现
	m := newMapping()
	masked := mask([]byte(text), m)
	ms := string(masked)

	// 长值 1234 必须完整脱敏，不能剩明文 4
	if strings.Contains(ms, "1234") {
		t.Fatalf("1234 not fully masked (短值拆长了): %s", ms)
	}
	// 独立出现的短值 123 也要被脱敏
	if strings.Contains(ms, "123") {
		t.Fatalf("独立 123 未脱敏: %s", ms)
	}
	// 还原必须逐字一致
	restored := restore(masked, m)
	if string(restored) != text {
		t.Fatalf("roundtrip mismatch:\n got: %s\nwant: %s", restored, text)
	}
	if strings.Contains(string(restored), "<<PII:") {
		t.Fatalf("placeholder leaked: %s", restored)
	}

	// 确定性：同一输入多次 mask 结果一致（不依赖 map 随机顺序）
	m2 := newMapping()
	ms2 := string(mask([]byte(text), m2))
	if ms != ms2 {
		t.Fatalf("nondeterministic masking:\n%s\n%s", ms, ms2)
	}
}

// 更长的包含链：映射 a / aa / aaa 同时存在，文本含长串也要完整还原。
func TestManualEntryNestedSubstrings(t *testing.T) {
	ResetPIIStore()
	globalStore.remember("a", "<<PII:UNKNOWN:1>>")
	globalStore.remember("aa", "<<PII:UNKNOWN:2>>")
	globalStore.remember("aaa", "<<PII:UNKNOWN:3>>")

	text := "前缀aaa中aa后缀a"
	m := newMapping()
	masked := mask([]byte(text), m)
	ms := string(masked)
	// 长值 aaa / aa 都应完整脱敏，不残留明文 a
	if strings.Contains(ms, "a") {
		t.Fatalf("明文 a 残留: %s", ms)
	}
	restored := restore(masked, m)
	if string(restored) != text {
		t.Fatalf("roundtrip mismatch:\n got: %s\nwant: %s", restored, text)
	}
	if strings.Contains(string(restored), "<<PII:") {
		t.Fatalf("placeholder leaked: %s", restored)
	}
}

// 同一个 PII 在文本里出现多次，只分配一个占位符，但所有出现位置都要还原。
func TestMaskRepeatedPII(t *testing.T) {
	ResetPIIStore()
	pii := "13955556666"
	text := "联系" + pii + "或" + pii + "，以及" + pii + "。"
	m := newMapping()
	masked := mask([]byte(text), m)
	ms := string(masked)
	if strings.Contains(ms, pii) {
		t.Fatalf("PII leaked: %s", ms)
	}
	if n := len(placeholderRe.FindAllString(ms, -1)); n != 3 {
		t.Fatalf("expected 3 placeholder occurrences, got %d: %s", n, ms)
	}
	// 只分配了 1 个唯一占位符
	if m.MaskedCount() != 1 {
		t.Fatalf("expected 1 unique PII, got %d", m.MaskedCount())
	}
	restored := restore(masked, m)
	if string(restored) != text {
		t.Fatalf("roundtrip mismatch:\n got: %s\nwant: %s", restored, text)
	}
}

// 4 开头的 18 位身份证不应被银行卡规则(4\d{15})截断成银行卡+残留明文。
// 身份证 [0-9]{17}[0-9X] 与银行卡 4\d{15} 重叠时，应按"最长匹配优先"识别为身份证。
func TestMaskIDCardNotTruncatedByBankCard(t *testing.T) {
	ResetPIIStore()
	ids := []string{
		"41052119980219553X", // 4 开头 18 位（Visa 卡前缀恰好重叠）
		"45080319990821666X", // 4 开头 18 位
		"110101199003071234", // 1 开头 18 位（无冲突）
	}
	for _, id := range ids {
		text := "身份证" + id
		m := newMapping()
		masked := mask([]byte(text), m)
		ms := string(masked)
		if strings.Contains(ms, id) {
			t.Fatalf("idcard not masked: %s", ms)
		}
		if !strings.Contains(ms, "<<PII:IDCARD:") {
			t.Fatalf("idcard should be IDCARD placeholder, got: %s", ms)
		}
		if strings.Contains(ms, "<<PII:BANKCARD:") {
			t.Fatalf("idcard wrongly tagged as BANKCARD: %s", ms)
		}
		// 必须是单个占位符，无明文残留（3X 等尾巴）
		if n := len(placeholderRe.FindAllString(ms, -1)); n != 1 {
			t.Fatalf("expected 1 placeholder, got %d: %s", n, ms)
		}
		restored := string(restore(masked, m))
		if restored != text {
			t.Fatalf("roundtrip mismatch:\n got: %s\nwant: %s", restored, text)
		}
	}
}

// 真实 19 位银联卡仍应整体识别为银行卡（不被身份证规则截断）。
func TestMaskBankCardStillWhole(t *testing.T) {
	ResetPIIStore()
	card := "6222021234567890123"
	text := "卡号" + card
	m := newMapping()
	masked := mask([]byte(text), m)
	ms := string(masked)
	if !strings.Contains(ms, "<<PII:BANKCARD:") {
		t.Fatalf("bank card should be BANKCARD: %s", ms)
	}
	if n := len(placeholderRe.FindAllString(ms, -1)); n != 1 {
		t.Fatalf("bank card should be one placeholder: %s", ms)
	}
	restored := string(restore(masked, m))
	if restored != text {
		t.Fatalf("roundtrip mismatch:\n got: %s\nwant: %s", restored, text)
	}
}
