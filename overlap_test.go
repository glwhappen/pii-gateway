package main

import (
	"strings"
	"testing"
)

// 重叠/边界数字串的核心安全属性：无论规则如何相互干扰，
// 往返后必须逐字一致、绝不残留占位符、内容不丢不坏。
//
// 已知限制（设计权衡，已文档化）：超长纯数字串可能被**部分脱敏**，剩明文尾巴，
// 例如 40 开头 20 位串剩末 6 位、19 位 2 开头纯数字剩末 1 位。
// 这些不造成还原错误，但意味着发往上游时仍有部分明文数字。
func TestMaskOverlapBoundary(t *testing.T) {
	cases := []struct {
		name string
		text string
	}{
		{"身份证以62开头", "62开头的身份证 620101199003071234 结尾"},
		{"40开头20位长串", "40开头的长串 4012345678901234567890"},
		{"座机不带横杠", "座机不带横杠 075512345678"},
		{"手机号前贴国码", "手机号前贴 86 13812345678 结尾"},
		{"18位纯数字", "18位纯数字 123456789012345678"},
		{"19位2开头纯数字", "19位纯数字 2222222222222222222"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ResetPIIStore()
			m := newMapping()
			masked := mask([]byte(tc.text), m)
			restored := restore(masked, m)

			// 往返必须逐字一致
			if string(restored) != tc.text {
				t.Fatalf("roundtrip mismatch:\n got: %s\nwant: %s", restored, tc.text)
			}
			// 还原后绝不允许残留占位符
			if strings.Contains(string(restored), "<<PII:") || strings.Contains(string(restored), "<<PI") {
				t.Fatalf("placeholder leaked after restore: %s", restored)
			}
			// 脱敏阶段必须至少产生占位符（确认有脱敏动作）
			if !strings.Contains(string(masked), "<<PII:") {
				t.Fatalf("no masking happened: %s", masked)
			}
		})
	}
}
