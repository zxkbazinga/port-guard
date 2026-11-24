package ikuai

import (
	"encoding/json"
	"fmt"
	"strings"
)

// 爱快提供两种源 IP 封禁手段：
//  1. 安全防护 → 黑名单（blacklist）：原生支持生效分钟数，到期自动失效 —— 首选
//  2. 访问控制 → ACL 规则（acl）：手动加一条 drop 规则，解封时删除该规则 —— 备选
//
// 由于固件版本间参数名有差异，这里对每种方式尝试若干参数形态，
// 探测成功后缓存，后续封禁直接使用已验证的形态。

type banVariant struct {
	Func     string
	Action   string
	Param    func(ip string, minutes int, reason string) map[string]any
	DelParam func(ip, ruleID string) map[string]any
}

var blacklistVariants = []banVariant{
	{
		Func: "blacklist", Action: "add",
		Param: func(ip string, minutes int, reason string) map[string]any {
			return map[string]any{"type": 4, "ip": ip, "timeout": minutes, "comment": reason}
		},
		DelParam: func(ip, ruleID string) map[string]any {
			if ruleID != "" {
				return map[string]any{"id": ruleID}
			}
			return map[string]any{"ip": ip}
		},
	},
	{
		Func: "blacklist", Action: "add",
		Param: func(ip string, minutes int, reason string) map[string]any {
			return map[string]any{"type": "ipv4", "ip": ip, "time": minutes, "comment": reason}
		},
		DelParam: func(ip, ruleID string) map[string]any {
			return map[string]any{"ip": ip}
		},
	},
	{
		Func: "blacklist", Action: "add",
		Param: func(ip string, minutes int, reason string) map[string]any {
			return map[string]any{"ip": ip, "timeout": minutes}
		},
		DelParam: func(ip, ruleID string) map[string]any {
			return map[string]any{"ip": ip}
		},
	},
}

func aclParam(ip string, _ int, reason string) map[string]any {
	return map[string]any{
		"tagname":    "port-guard:" + ip,
		"action":     "deny",
		"protocol":   "all",
		"dir":        "in",
		"iinterface": "any",
		"ointerface": "any",
		"ip_type":    "4",
		"prio":       5,
		"enabled":    "yes",
		"comment":    reason,
		"src_addr":   map[string]any{"custom": []string{ip}, "object": []any{}},
		"dst_addr":   map[string]any{"custom": []string{}, "object": []any{}},
		"src_port":   map[string]any{"custom": []string{}, "object": []any{}},
		"dst_port":   map[string]any{"custom": []string{}, "object": []any{}},
	}
}

var aclVariants = []banVariant{{
	Func: "acl", Action: "add", Param: aclParam,
	DelParam: func(ip, ruleID string) map[string]any {
		if ruleID != "" {
			return map[string]any{"id": ruleID}
		}
		return map[string]any{"tagname": "port-guard:" + ip}
	},
}}

// resolveMode 确定使用哪种封禁方式。mode 可以是 auto / blacklist / acl / none。
func (c *Client) resolveMode() (string, error) {
	c.mu.Lock()
	if c.probeTried {
		mode := c.banMode
		c.mu.Unlock()
		if mode == "" {
			return "", fmt.Errorf("未找到可用的封禁方式，请检查爱快 API 权限或手动指定 ban_mode")
		}
		return mode, nil
	}
	c.probeTried = true
	c.mu.Unlock()

	mode := c.cfg.BanMode()
	switch mode {
	case "none":
		c.mu.Lock()
		c.banMode = "none"
		c.mu.Unlock()
		return "none", nil
	case "blacklist", "acl":
		if err := c.verifyMode(mode); err != nil {
			return "", err
		}
		c.mu.Lock()
		c.banMode = mode
		c.mu.Unlock()
		return mode, nil
	default: // auto
		for _, candidate := range []string{"blacklist", "acl"} {
			if err := c.verifyMode(candidate); err == nil {
				c.mu.Lock()
				c.banMode = candidate
				c.mu.Unlock()
				c.log.Info("爱快封禁方式探测成功", "mode", candidate)
				return candidate, nil
			}
		}
		c.mu.Lock()
		c.banMode = ""
		c.mu.Unlock()
		return "", fmt.Errorf("自动探测失败：blacklist 与 acl 接口均不可用")
	}
}

// verifyMode 用一个测试 IP 验证接口是否接受参数，随后删除测试项。
func (c *Client) verifyMode(mode string) error {
	testIP := "203.0.113.254" // RFC5737 文档地址，不会真实命中
	variants := blacklistVariants
	if mode == "acl" {
		variants = aclVariants
	}
	var lastErr error
	for _, v := range variants {
		data, err := c.Call(v.Func, v.Action, v.Param(testIP, 1, "port-guard probe"))
		if err != nil {
			lastErr = err
			continue
		}
		if !apiOK(data) {
			lastErr = fmt.Errorf("接口返回失败: %s", string(data))
			continue
		}
		// 清理探测记录
		_, _ = c.Call(v.Func, "del", v.DelParam(testIP, ""))
		c.mu.Lock()
		c.probeVariant = v
		c.mu.Unlock()
		return nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("无可用参数形态")
	}
	return fmt.Errorf("%s 接口不可用: %w", mode, lastErr)
}

// Ban 封禁源 IP，minutes<=0 时使用配置的默认时长。返回可用于解封的规则 ID。
func (c *Client) Ban(ip string, minutes int, reason string) (string, error) {
	if minutes <= 0 {
		minutes = c.cfg.BanMinutes()
	}
	mode, err := c.resolveMode()
	if err != nil {
		return "", err
	}
	if mode == "none" {
		return "", nil
	}
	c.mu.Lock()
	variant := c.probeVariant
	c.mu.Unlock()
	if variant.Func == "" {
		variants := blacklistVariants
		if mode == "acl" {
			variants = aclVariants
		}
		variant = variants[0]
	}
	data, err := c.Call(variant.Func, variant.Action, variant.Param(ip, minutes, reason))
	if err != nil {
		return "", err
	}
	if !apiOK(data) {
		return "", fmt.Errorf("封禁 %s 失败: %s", ip, string(data))
	}
	ruleID := extractRuleID(data)
	c.log.Warn("已封禁源 IP", "ip", ip, "minutes", minutes, "reason", reason, "mode", mode)
	return ruleID, nil
}

// Unban 解除封禁。
func (c *Client) Unban(ip, ruleID string) error {
	mode, err := c.resolveMode()
	if err != nil {
		return err
	}
	if mode == "none" {
		return nil
	}
	c.mu.Lock()
	variant := c.probeVariant
	c.mu.Unlock()
	if variant.Func == "" {
		variants := blacklistVariants
		if mode == "acl" {
			variants = aclVariants
		}
		variant = variants[0]
	}
	data, err := c.Call(variant.Func, "del", variant.DelParam(ip, ruleID))
	if err != nil {
		return err
	}
	if !apiOK(data) {
		return fmt.Errorf("解封 %s 失败: %s", ip, string(data))
	}
	c.log.Info("已解除封禁", "ip", ip)
	return nil
}

// Mode 返回当前探测到的封禁方式（供状态页展示）。
func (c *Client) Mode() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.banMode == "" {
		return "未探测"
	}
	return c.banMode
}

// ResetProbe 配置变更后重置探测结果。
func (c *Client) ResetProbe() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.probeTried = false
	c.banMode = ""
	c.probeVariant = banVariant{}
	c.session = ""
}

func extractRuleID(data json.RawMessage) string {
	var obj map[string]any
	if json.Unmarshal(data, &obj) != nil {
		return ""
	}
	for _, key := range []string{"id", "rowid", "rule_id", "Result"} {
		if v, ok := obj[key]; ok {
			s := strings.TrimSpace(fmt.Sprint(v))
			if s != "" && s != "0" && s != "<nil>" {
				return s
			}
		}
	}
	if rows := extractRows(data, "data", "result"); len(rows) > 0 {
		for _, key := range []string{"id", "rowid"} {
			if v, ok := rows[0][key]; ok {
				return strings.TrimSpace(fmt.Sprint(v))
			}
		}
	}
	return ""
}
