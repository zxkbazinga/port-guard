// Package textutil 提供跨模块共用的文本清洗函数。
package textutil

import (
	"net/url"
	"strings"
)

// DecodeURLEscaped 还原被 URL 转义的文本。
// 爱快接口返回的备注常见形态：DSM%20SSH、%E4%B8%AD%E6%96%87，偶尔还会双重转义。
// 最多解码两层；非法转义（如单独的 %）保持原样；不会把 '+' 当空格，避免误改 "C++" 这类备注。
func DecodeURLEscaped(s string) string {
	if !strings.Contains(s, "%") {
		return s
	}
	out := s
	for i := 0; i < 2; i++ {
		next, err := url.PathUnescape(out)
		if err != nil || next == out {
			break
		}
		out = next
	}
	return out
}
