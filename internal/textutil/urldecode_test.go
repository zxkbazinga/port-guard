package textutil

import "testing"

func TestDecodeURLEscaped(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"DSM%20SSH", "DSM SSH"},
		{"%E4%B8%AD%E6%96%87%E5%A4%87%E6%B3%A8", "中文备注"},
		{"DSM%2520SSH", "DSM SSH"}, // 双重转义
		{"C++", "C++"},             // 不能把加号当空格
		{"100% done", "100% done"}, // 非法转义保持原样
		{"", ""},
	}
	for _, c := range cases {
		if got := DecodeURLEscaped(c.in); got != c.want {
			t.Errorf("DecodeURLEscaped(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
