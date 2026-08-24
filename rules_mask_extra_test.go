package main

import (
	"strings"
	"testing"
)

// 补充规则（港澳通行证/信用代码/网络地址/凭证等）单条完整往返 + 占位符类型标签断言。
func TestMaskExtraRulesRoundTrip(t *testing.T) {
	cases := []struct{ name, typ, pii string }{
		{"港澳通行证", "HKMO_PASS", "M12345678"}, // M 开头避开护照规则 [eghpsd] 抢占
		{"统一社会信用代码", "CREDIT_CODE", "91310115MA1K3N5D6X"},
		{"组织机构代码", "ORG_CODE", "12345678-9"},
		{"IPv4", "IPV4", "192.168.1.100"},
		{"IPv6", "IPV6", "2001:0db8:85a3:0000:0000:8a2e:0370:7334"},
		{"MAC", "MAC", "aa:bb:cc:dd:ee:ff"},
		{"JWT", "JWT", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"},
		{"Bearer", "BEARER", "Bearer abcdefghijklmnopqrstuvwxyz"}, // token 不以 eyJ 开头, 避免被 JWT 抢占
		{"OpenAI Key", "API_KEY", "sk-abcdefghijklmnopqrstuvwxyz123456"},
		{"GitHub Token", "GITHUB_TOKEN", "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ123456"},
		{"AWS Key", "AWS_KEY", "AKIAIOSFODNN7EXAMPLE"},
		{"美国SSN", "SSN_US", "123-45-6789"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ResetPIIStore()
			text := "信息：" + tc.pii + " 请保密"
			m := newMapping()
			masked := mask([]byte(text), m)
			if strings.Contains(string(masked), tc.pii) {
				t.Fatalf("not masked: %s", masked)
			}
			// 占位符类型标签必须正确
			ph := placeholderRe.FindString(string(masked))
			if !strings.HasPrefix(ph, "<<PII:"+tc.typ+":") {
				t.Fatalf("wrong type label %q (want %s): %s", ph, tc.typ, masked)
			}
			restored := restore(masked, m)
			if string(restored) != text {
				t.Fatalf("roundtrip:\n got: %s\nwant: %s", restored, text)
			}
			if strings.Contains(string(restored), "<<PII:") {
				t.Fatalf("leak: %s", restored)
			}
		})
	}
}

// PEM 私钥为多行块，应整体脱敏并完整还原。
func TestMaskPEMPrivateKey(t *testing.T) {
	ResetPIIStore()
	pem := "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAx\nabcdefghijklmnopqrstuvwxyz\n-----END RSA PRIVATE KEY-----"
	text := "私钥：\n" + pem + "\n请妥善保管。"
	m := newMapping()
	masked := mask([]byte(text), m)
	ms := string(masked)
	if strings.Contains(ms, "BEGIN RSA PRIVATE KEY") {
		t.Fatalf("PEM 未脱敏: %s", ms)
	}
	if n := len(placeholderRe.FindAllString(ms, -1)); n != 1 {
		t.Fatalf("PEM 应整体一个占位符, got %d: %s", n, ms)
	}
	restored := restore(masked, m)
	if string(restored) != text {
		t.Fatalf("roundtrip:\n got: %s\nwant: %s", restored, text)
	}
	if strings.Contains(string(restored), "<<PII:") {
		t.Fatalf("leak: %s", restored)
	}
}

// 综合中文场景：姓名(名单) + 各类号码 + 网络/凭证一起，全部脱敏还原。
func TestMaskComprehensiveChineseText(t *testing.T) {
	ResetPIIStore()
	oldNames := namesList
	defer func() { namesList = oldNames }()
	namesList = []string{"张三丰"}

	text := "我是张三丰，电话13812345678，身份证110101199003071234，" +
		"邮箱zhangsan@test.com，公司统一信用代码91310115MA1K3N5D6X，" +
		"服务器IP 203.0.113.9，MAC aa-bb-cc-dd-ee-ff，" +
		"调用openai需要key：sk-abcdefghijklmnopqrstuvwxyz123456。"
	m := newMapping()
	masked := mask([]byte(text), m)
	ms := string(masked)
	for _, p := range []string{
		"张三丰", "13812345678", "110101199003071234", "zhangsan@test.com",
		"91310115MA1K3N5D6X", "203.0.113.9", "aa-bb-cc-dd-ee-ff",
		"sk-abcdefghijklmnopqrstuvwxyz123456",
	} {
		if strings.Contains(ms, p) {
			t.Fatalf("PII not masked (%s): %s", p, ms)
		}
	}
	// 姓名应生成 NAME 类型占位符
	if !strings.Contains(ms, "<<PII:NAME:") {
		t.Fatalf("姓名未用 NAME 类型: %s", ms)
	}
	restored := restore(masked, m)
	if string(restored) != text {
		t.Fatalf("roundtrip:\n got: %s\nwant: %s", restored, text)
	}
	if strings.Contains(string(restored), "<<PII:") {
		t.Fatalf("leak: %s", restored)
	}
}

// 确定性：相同输入在独立请求间（新 mapping）复用同一占位符，结果一致。
func TestMaskDeterministicAcrossRequests(t *testing.T) {
	ResetPIIStore()
	text := "电话13812345678 与 邮箱u@test.com"
	var first string
	for i := 0; i < 3; i++ {
		m := newMapping()
		ms := string(mask([]byte(text), m))
		if first == "" {
			first = ms
		} else if ms != first {
			t.Fatalf("同一内容跨请求占位符应一致:\n%s\n%s", ms, first)
		}
	}
}

// 忽略与名单交互：名单词被忽略后不再掩码，取消后恢复。
func TestIgnoreInteractsWithNames(t *testing.T) {
	ResetPIIStore()
	oldNames := namesList
	defer func() { namesList = oldNames }()
	namesList = []string{"李四"}
	globalStore.remember("李四", "<<PII:NAME:1>>")

	// 忽略该名单词
	if err := globalStore.setIgnored("<<PII:NAME:1>>", true); err != nil {
		t.Fatalf("setIgnored: %v", err)
	}
	m := newMapping()
	if out := string(mask([]byte("我是李四"), m)); !strings.Contains(out, "李四") {
		t.Fatalf("忽略后名单词仍被掩码: %s", out)
	}

	// 取消忽略
	if err := globalStore.setIgnored("<<PII:NAME:1>>", false); err != nil {
		t.Fatalf("unignore: %v", err)
	}
	m2 := newMapping()
	if out := string(mask([]byte("我是李四"), m2)); strings.Contains(out, "李四") {
		t.Fatalf("取消忽略后未恢复掩码: %s", out)
	}
}
