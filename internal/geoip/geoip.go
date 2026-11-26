// Package geoip 提供基于 APNIC 官方分配表的离线来源地区判定。
// 数据编译进二进制，运行时不查询外部接口，不产生延迟或隐私泄露。
package geoip

import (
	"bufio"
	"bytes"
	"embed"
	"net/netip"
	"strings"
)

// 来源地区限制模式。
const (
	ModeOff   = "off"    // 不限制
	ModeCN    = "cn"     // 仅中国大陆
	ModeCNAll = "cn_all" // 中国大陆 + 中国香港 + 中国澳门 + 中国台湾
)

const (
	flagCN      uint8 = 1 << iota
	flagRegions       // 中国香港 / 中国澳门 / 中国台湾
)

//go:embed data/blocks.txt
var blocksFS embed.FS

// NormalizeMode 把外部传入的模式收敛为已知值，未知值按“不限制”处理。
func NormalizeMode(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case ModeCN:
		return ModeCN
	case ModeCNAll:
		return ModeCNAll
	default:
		return ModeOff
	}
}

type node struct {
	child [2]*node
	flags uint8
}

// trie 是一棵按地址比特逐位展开的前缀树。v4 深度 32，v6 深度 128。
type trie struct {
	root  *node
	depth int
}

func newTrie(depth int) *trie {
	return &trie{root: &node{}, depth: depth}
}

func (t *trie) insert(prefix netip.Prefix, flags uint8) {
	prefix = prefix.Masked()
	bits := prefix.Bits()
	if bits < 0 || bits > t.depth {
		return
	}
	addr := prefix.Addr()
	var raw []byte
	if addr.Is4() {
		a := addr.As4()
		raw = a[:]
	} else if addr.Is6() && !addr.Is4In6() {
		a := addr.As16()
		raw = a[:]
	} else {
		return
	}
	cur := t.root
	for i := 0; i < bits; i++ {
		idx := bitAt(raw, i)
		if cur.child[idx] == nil {
			cur.child[idx] = &node{}
		}
		cur = cur.child[idx]
	}
	cur.flags |= flags
}

// contains 沿地址比特路径查找，任一前缀节点命中目标标记即放行。
func (t *trie) contains(ip netip.Addr, want uint8) bool {
	var raw []byte
	if ip.Is4() {
		a := ip.As4()
		raw = a[:]
	} else if ip.Is6() && !ip.Is4In6() {
		a := ip.As16()
		raw = a[:]
	} else {
		return false
	}
	cur := t.root
	for i := 0; i < t.depth && cur != nil; i++ {
		if cur.flags&want != 0 {
			return true
		}
		cur = cur.child[bitAt(raw, i)]
	}
	return cur != nil && cur.flags&want != 0
}

func bitAt(raw []byte, i int) int {
	return int((raw[i/8] >> (7 - uint(i%8))) & 1)
}

// Checker 持有编译期加载的地区前缀树与国家归属索引，可并发使用。
type Checker struct {
	v4        *trie
	v6        *trie
	countries *countryIndex
}

// New 从内嵌的 APNIC 分配表构建前缀树与国家归属索引。
func New() (*Checker, error) {
	raw, err := blocksFS.ReadFile("data/blocks.txt")
	if err != nil {
		return nil, err
	}
	countries, err := newCountryIndex()
	if err != nil {
		return nil, err
	}
	c := &Checker{v4: newTrie(32), v6: newTrie(128), countries: countries}
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		prefix, err := netip.ParsePrefix(fields[0])
		if err != nil {
			return nil, err
		}
		flags := flagRegions
		if fields[1] == "CN" {
			flags = flagCN
		}
		if prefix.Addr().Is4() {
			c.v4.insert(prefix, flags)
		} else {
			c.v6.insert(prefix, flags)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return c, nil
}

// Country 返回 IP 的归属国家/地区中文名（私网返回「内网」，未知返回「未知」）。
func (c *Checker) Country(ip string) string {
	if c == nil || c.countries == nil {
		return "未知"
	}
	return c.countries.lookup(ip)
}

// Allows 判断来源 IP 在该模式下是否允许连接。
// 私网/环回/链路本地/组播地址以及无法解析的地址一律放行，避免误伤内网访问；
// 真正的拦截只发生在公网来源上。
func (c *Checker) Allows(ipStr, mode string) bool {
	mode = NormalizeMode(mode)
	if mode == ModeOff {
		return true
	}
	ip, err := netip.ParseAddr(ipStr)
	if err != nil {
		return true
	}
	ip = ip.Unmap()
	if !ip.IsValid() || !ip.IsGlobalUnicast() || ip.IsPrivate() ||
		ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsMulticast() || ip.IsUnspecified() {
		return true
	}
	want := flagCN
	if mode == ModeCNAll {
		want = flagCN | flagRegions
	}
	if ip.Is4() {
		return c.v4.contains(ip, want)
	}
	return c.v6.contains(ip, want)
}
