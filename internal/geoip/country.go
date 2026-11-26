package geoip

import (
	"bufio"
	"bytes"
	"embed"
	"net/netip"
	"sort"
	"strconv"
	"strings"
)

//go:embed data/countries.txt
var countriesFS embed.FS

// countryBlock 是排序数组中的一条 CIDR → 国家索引记录。
// 用 uint32/[16]byte + uint8 国家索引紧凑存储，避免每条保存字符串。
type countryBlock struct {
	addr [16]byte // v4 用前 4 字节，v6 用 16 字节，按网络序
	bits uint8
	code uint8 // 国家索引，0..len(codes)-1
	isV4 bool
}

func (b countryBlock) prefix() netip.Prefix {
	var addr netip.Addr
	if b.isV4 {
		addr = netip.AddrFrom4([4]byte{b.addr[0], b.addr[1], b.addr[2], b.addr[3]})
	} else {
		addr = netip.AddrFrom16(b.addr)
	}
	return netip.PrefixFrom(addr, int(b.bits)).Masked()
}

// countryNames 把 ISO-3166-1 alpha-2 代码映射为中文名。
// 未列出的代码回退为代码本身，避免数据更新后出现空值。
var countryNames = map[string]string{
	"AF": "阿富汗", "AL": "阿尔巴尼亚", "DZ": "阿尔及利亚", "AR": "阿根廷", "AM": "亚美尼亚",
	"AU": "澳大利亚", "AT": "奥地利", "AZ": "阿塞拜疆", "BH": "巴林", "BD": "孟加拉国",
	"BY": "白俄罗斯", "BE": "比利时", "BO": "玻利维亚", "BA": "波黑", "BR": "巴西",
	"BG": "保加利亚", "KH": "柬埔寨", "CA": "加拿大", "CL": "智利", "CN": "中国大陆",
	"CO": "哥伦比亚", "CR": "哥斯达黎加", "HR": "克罗地亚", "CU": "古巴", "CY": "塞浦路斯",
	"CZ": "捷克", "DK": "丹麦", "DO": "多米尼加", "EC": "厄瓜多尔", "EG": "埃及",
	"SV": "萨尔瓦多", "EE": "爱沙尼亚", "ET": "埃塞俄比亚", "FI": "芬兰", "FR": "法国",
	"GE": "格鲁吉亚", "DE": "德国", "GR": "希腊", "GT": "危地马拉", "HK": "中国香港",
	"HN": "洪都拉斯", "HU": "匈牙利", "IS": "冰岛", "IN": "印度", "ID": "印度尼西亚",
	"IR": "伊朗", "IQ": "伊拉克", "IE": "爱尔兰", "IL": "以色列", "IT": "意大利",
	"JP": "日本", "JO": "约旦", "KZ": "哈萨克斯坦", "KE": "肯尼亚", "KR": "韩国",
	"KP": "朝鲜", "KW": "科威特", "KG": "吉尔吉斯斯坦", "LA": "老挝", "LV": "拉脱维亚",
	"LB": "黎巴嫩", "LT": "立陶宛", "LU": "卢森堡", "MO": "中国澳门", "MK": "北马其顿",
	"MY": "马来西亚", "MT": "马耳他", "MX": "墨西哥", "MD": "摩尔多瓦", "MN": "蒙古",
	"MA": "摩洛哥", "MZ": "莫桑比克", "MM": "缅甸", "NP": "尼泊尔", "NL": "荷兰",
	"NZ": "新西兰", "NI": "尼加拉瓜", "NG": "尼日利亚", "NO": "挪威", "OM": "阿曼",
	"PK": "巴基斯坦", "PA": "巴拿马", "PY": "巴拉圭", "PE": "秘鲁", "PH": "菲律宾",
	"PL": "波兰", "PT": "葡萄牙", "QA": "卡塔尔", "RO": "罗马尼亚", "RU": "俄罗斯",
	"SA": "沙特阿拉伯", "SN": "塞内加尔", "RS": "塞尔维亚", "SG": "新加坡", "SK": "斯洛伐克",
	"SI": "斯洛文尼亚", "ZA": "南非", "ES": "西班牙", "LK": "斯里兰卡", "SD": "苏丹",
	"SE": "瑞典", "CH": "瑞士", "SY": "叙利亚", "TW": "中国台湾", "TJ": "塔吉克斯坦",
	"TH": "泰国", "TN": "突尼斯", "TR": "土耳其", "TM": "土库曼斯坦", "AE": "阿联酋",
	"GB": "英国", "US": "美国", "UY": "乌拉圭", "UZ": "乌兹别克斯坦", "VE": "委内瑞拉",
	"VN": "越南", "YE": "也门", "ZM": "赞比亚", "ZW": "津巴布韦",
}

// countryIndex 持有全球 CIDR 的排序紧凑数组，用于按 IP 反查国家。
type countryIndex struct {
	v4    []countryBlock
	v6    []countryBlock
	codes []string
}

func newCountryIndex() (*countryIndex, error) {
	raw, err := countriesFS.ReadFile("data/countries.txt")
	if err != nil {
		return nil, err
	}
	idx := &countryIndex{}
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	section := ""
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			if strings.HasPrefix(line, "#code-index") {
				section = "codes"
			} else if strings.HasPrefix(line, "#blocks") {
				section = "blocks"
			}
			continue
		}
		fields := strings.Fields(line)
		if section == "codes" && len(fields) >= 2 {
			idx.codes = append(idx.codes, fields[1])
			continue
		}
		if section != "blocks" || len(fields) < 4 {
			continue
		}
		version, _ := strconv.Atoi(fields[0])
		bits, _ := strconv.Atoi(fields[2])
		code, _ := strconv.Atoi(fields[3])
		addr, err := netip.ParseAddr(fields[1])
		if err != nil {
			return nil, err
		}
		b := countryBlock{bits: uint8(bits), code: uint8(code), isV4: version == 4}
		if b.isV4 {
			a := addr.As4()
			copy(b.addr[:4], a[:])
			idx.v4 = append(idx.v4, b)
		} else {
			a := addr.As16()
			b.addr = a
			idx.v6 = append(idx.v6, b)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	less := func(blocks []countryBlock) {
		sort.Slice(blocks, func(i, j int) bool {
			ai, aj := blocks[i], blocks[j]
			for k := 0; k < 16; k++ {
				if ai.addr[k] != aj.addr[k] {
					return ai.addr[k] < aj.addr[k]
				}
			}
			return ai.bits < aj.bits
		})
	}
	less(idx.v4)
	less(idx.v6)
	return idx, nil
}

// addrBytes 把 IP 转成与 countryBlock.addr 同序的字节数组。
func addrBytes(ip netip.Addr) [16]byte {
	var out [16]byte
	if ip.Is4() {
		a := ip.As4()
		copy(out[:4], a[:])
	} else {
		out = ip.As16()
	}
	return out
}

// lookup 返回 IP 的国家中文名。私网/环回返回 "内网"，无法识别返回 "未知"。
// 二分定位到最后一个起始地址不超过 ip 的块，再向前回退有限步找最长匹配前缀，
// 兼容分配表中偶发的嵌套 CIDR。
func (idx *countryIndex) lookup(ipStr string) string {
	ip, err := netip.ParseAddr(ipStr)
	if err != nil {
		return "未知"
	}
	ip = ip.Unmap()
	if !ip.IsValid() {
		return "未知"
	}
	if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() ||
		ip.IsLinkLocalUnicast() || ip.IsMulticast() || ip.IsUnspecified() {
		return "内网"
	}
	blocks := idx.v6
	if ip.Is4() {
		blocks = idx.v4
	}
	if len(blocks) == 0 {
		return "未知"
	}
	target := addrBytes(ip)
	hi := sort.Search(len(blocks), func(i int) bool {
		return bytes.Compare(blocks[i].addr[:], target[:]) > 0
	})
	for i := hi - 1; i >= 0 && i >= hi-64; i-- {
		if blocks[i].prefix().Contains(ip) {
			code := ""
			if int(blocks[i].code) < len(idx.codes) {
				code = idx.codes[blocks[i].code]
			}
			if name, ok := countryNames[code]; ok {
				return name
			}
			if code == "" {
				return "未知"
			}
			return code
		}
	}
	return "未知"
}
