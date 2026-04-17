package waftunnelengine

import (
	"SamWaf/common/zlog"
	"SamWaf/model"
	"SamWaf/utils"
	"fmt"
	"net"
	"strings"
)

// IPCheckResult IP检查结果
type IPCheckResult struct {
	Allow    bool   // 是否允许访问
	RuleName string // 拦截原因，如 "【隧道】IP黑名单"、"【隧道】网站防护黑名单" 等
}

// CheckIPAccess 检查IP是否允许访问
// 参数: protocol 协议类型(TCP/UDP), clientIP 客户端IP, clientPort 客户端端口, serverPort 服务端口, tunnel 隧道配置, waf 隧道引擎对象
// 返回值: IPCheckResult 包含是否允许和拦截原因
func CheckIPAccess(protocol string, clientIP string, clientPort string, serverPort string, tunnel model.Tunnel, waf *WafTunnelEngine) IPCheckResult {
	// 如果客户端IP为空，拒绝访问
	if clientIP == "" {
		zlog.Warn(fmt.Sprintf("客户端IP为空，拒绝访问 [协议:%s 客户端IP:%s 客户端端口:%s 服务端口:%s]",
			protocol, clientIP, clientPort, serverPort))
		return IPCheckResult{Allow: false, RuleName: "【隧道】客户端IP为空"}
	}

	// 处理IP地址，去除端口部分（如果传入的是完整地址）
	if strings.Contains(clientIP, ":") {
		host, _, err := net.SplitHostPort(clientIP)
		if err != nil {
			zlog.Error(fmt.Sprintf("解析客户端IP失败 [协议:%s 客户端IP:%s 客户端端口:%s 服务端口:%s 错误:%s]",
				protocol, clientIP, clientPort, serverPort, err.Error()))
			return IPCheckResult{Allow: false, RuleName: "【隧道】客户端IP解析失败"}
		}
		clientIP = host
	}

	// 检查黑名单（优先级高）
	if tunnel.DenyIp != "" {
		denyIPs := strings.Split(tunnel.DenyIp, ",")
		for _, ip := range denyIPs {
			ip = strings.TrimSpace(ip)
			if ip == "" {
				continue
			}

			// 支持CIDR格式和精确匹配
			if strings.Contains(ip, "/") {
				// CIDR格式
				_, ipNet, err := net.ParseCIDR(ip)
				if err == nil && ipNet.Contains(net.ParseIP(clientIP)) {
					zlog.Info(fmt.Sprintf("IP在黑名单CIDR范围内，拒绝访问 [协议:%s 客户端IP:%s 客户端端口:%s 服务端口:%s CIDR:%s]",
						protocol, clientIP, clientPort, serverPort, ip))
					return IPCheckResult{Allow: false, RuleName: "【隧道】IP黑名单"}
				}
			} else if ip == clientIP {
				// 精确匹配
				zlog.Info(fmt.Sprintf("IP在黑名单中，拒绝访问 [协议:%s 客户端IP:%s 客户端端口:%s 服务端口:%s]",
					protocol, clientIP, clientPort, serverPort))
				return IPCheckResult{Allow: false, RuleName: "【隧道】IP黑名单"}
			}
		}
	}

	// 检查网站防护IP黑名单（全局+所有网站局部）
	if waf != nil && waf.GlobalIPBlockLists != nil {
		allBlockLists := waf.GlobalIPBlockLists.GetAllBlockLists()
		for i := 0; i < len(allBlockLists); i++ {
			if utils.CheckIPInCIDR(clientIP, allBlockLists[i].Ip) {
				zlog.Info(fmt.Sprintf("IP在网站防护黑名单中，拒绝隧道访问 [协议:%s 客户端IP:%s 客户端端口:%s 服务端口:%s]",
					protocol, clientIP, clientPort, serverPort))
				return IPCheckResult{Allow: false, RuleName: "【隧道】网站防护黑名单"}
			}
		}
	}

	// 检查白名单
	if tunnel.AllowIp != "" {
		// 白名单不为空，需要在白名单中才允许访问
		allowIPs := strings.Split(tunnel.AllowIp, ",")
		for _, ip := range allowIPs {
			ip = strings.TrimSpace(ip)
			if ip == "" {
				continue
			}

			// 支持CIDR格式和精确匹配
			if strings.Contains(ip, "/") {
				// CIDR格式
				_, ipNet, err := net.ParseCIDR(ip)
				if err == nil && ipNet.Contains(net.ParseIP(clientIP)) {
					zlog.Info(fmt.Sprintf("IP在白名单CIDR范围内，允许访问 [协议:%s 客户端IP:%s 客户端端口:%s 服务端口:%s CIDR:%s]",
						protocol, clientIP, clientPort, serverPort, ip))
					return IPCheckResult{Allow: true, RuleName: ""}
				}
			} else if ip == clientIP {
				// 精确匹配
				zlog.Info(fmt.Sprintf("IP在白名单中，允许访问 [协议:%s 客户端IP:%s 客户端端口:%s 服务端口:%s]",
					protocol, clientIP, clientPort, serverPort))
				return IPCheckResult{Allow: true, RuleName: ""}
			}
		}

		// 如果有白名单但IP不在其中，拒绝访问
		zlog.Info(fmt.Sprintf("IP不在白名单中，拒绝访问 [协议:%s 客户端IP:%s 客户端端口:%s 服务端口:%s]",
			protocol, clientIP, clientPort, serverPort))
		return IPCheckResult{Allow: false, RuleName: "【隧道】IP白名单限制"}
	}

	// 如果没有设置白名单，且不在黑名单中，则允许访问
	zlog.Info(fmt.Sprintf("隧道访问通过访问控制检查，允许访问 [协议:%s 客户端IP:%s 客户端端口:%s 服务端口:%s]",
		protocol, clientIP, clientPort, serverPort))
	return IPCheckResult{Allow: true, RuleName: ""}
}