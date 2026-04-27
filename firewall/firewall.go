//go:build linux

package firewall

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

type Charset string

const (
	UTF8    = Charset("UTF-8")
	GB18030 = Charset("GB18030")
)

const ACTION_ALLOW string = "allow"
const ACTION_BLOCK string = "block"
const ACTION_BYPASS string = "bypass"

const (
	PROTOCOL_ANY   = "any"  // 任意协议
	PROTOCOL_TCP   = "TCP"  // TCP 协议
	PROTOCOL_UDP   = "UDP"  // UDP 协议
	DIRECTION_IN   = "in"   // 入站
	DIRECTION_OUT  = "out"  // 出站
	DIRECTION_BOTH = "both" // 双向
)

const (
	RULE_PREFIX                  = "SamWAF_Block_" // 规则名称前缀
	FIREWALLD_RICH_RULE_PRIORITY = "10"            // rich rule 优先级
)

type FireWallEngine struct{}

// IPBlockInfo IP封禁信息结构
type IPBlockInfo struct {
	IP        string    // IP地址
	Reason    string    // 封禁原因
	BlockTime time.Time // 封禁时间
	Protocol  string    // 协议类型
	Direction string    // 方向
}

// detectFirewallBackend 检测系统使用的防火墙后端
// 返回 "firewalld" 或 "iptables"
func detectFirewallBackend() string {
	// 检查 firewalld 是否运行
	path, err := findExecutable("firewall-cmd")
	if err == nil {
		cmd := exec.Command(path, "--state")
		output, err := cmd.CombinedOutput()
		if err == nil && strings.TrimSpace(string(output)) == "running" {
			return "firewalld"
		}
	}
	return "iptables"
}

// cachedBackend 缓存的防火墙后端类型
var cachedBackend string

// getFirewallBackend 获取防火墙后端（带缓存）
func getFirewallBackend() string {
	if cachedBackend == "" {
		cachedBackend = detectFirewallBackend()
		fmt.Printf("[INFO] 检测到防火墙后端: %s\n", cachedBackend)
	}
	return cachedBackend
}

// iptablesSearchPaths iptables相关命令的搜索路径
var iptablesSearchPaths = []string{
	"/usr/sbin", "/sbin", "/usr/local/sbin",
	"/usr/bin", "/bin", "/usr/local/bin",
}

// findExecutable 在已知路径和PATH中查找可执行文件
func findExecutable(name string) (string, error) {
	// 先尝试 PATH 查找
	if path, err := exec.LookPath(name); err == nil {
		return path, nil
	}

	// 在常见 sbin 目录中手动搜索
	for _, dir := range iptablesSearchPaths {
		fullPath := dir + "/" + name
		info, err := os.Stat(fullPath)
		if err == nil && !info.IsDir() {
			// 检查文件是否可执行
			if info.Mode()&0111 != 0 {
				return fullPath, nil
			}
		}
	}

	return "", fmt.Errorf("executable %s not found in PATH or known sbin directories", name)
}

func (fw *FireWallEngine) IsFirewallEnabled() bool {
	if runtime.GOOS == "linux" {
		backend := getFirewallBackend()
		if backend == "firewalld" {
			path, err := findExecutable("firewall-cmd")
			if err != nil {
				return false
			}
			output, err := exec.Command(path, "--state").CombinedOutput()
			if err != nil {
				return false
			}
			return strings.TrimSpace(string(output)) == "running"
		}
		// iptables 方式
		path, err := findExecutable("iptables")
		if err != nil {
			return false
		}
		out, err := exec.Command(path, "-L").CombinedOutput()
		if err != nil {
			return false
		}
		return len(out) > 0
	}
	return false
}

func (fw *FireWallEngine) executeCommand(cmd *exec.Cmd) (error, string) {
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		fmt.Println(err)
		return err, err.Error()
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		fmt.Println(err)
		return err, err.Error()
	}
	if err := cmd.Start(); err != nil {
		fmt.Println(err)
		return err, err.Error()
	}
	var printstr string
	in := bufio.NewScanner(stdout)
	for in.Scan() {
		printstr += in.Text() + "\n"
	}
	errScanner := bufio.NewScanner(stderr)
	for errScanner.Scan() {
		printstr += errScanner.Text() + "\n"
	}
	waitErr := cmd.Wait()
	if waitErr != nil {
		return waitErr, printstr
	}
	return nil, printstr
}

// isIPInRulesFirewalld 通过 firewall-cmd 检查 IP 是否已被封禁
func (fw *FireWallEngine) isIPInRulesFirewalld(ip string) (bool, error) {
	path, err := findExecutable("firewall-cmd")
	if err != nil {
		return false, fmt.Errorf("failed to find firewall-cmd: %v", err)
	}

	// 使用 --list-rich-rules 获取所有 rich rules
	cmd := exec.Command(path, "--list-rich-rules")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return false, fmt.Errorf("failed to list firewalld rich rules: %v", err)
	}

	outputStr := string(output)
	ruleName := generateRuleName(ip)

	// 每条 rich rule 是一行，检查是否存在包含该规则名的 rich rule
	lines := strings.Split(outputStr, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "source address=\""+ip+"\"") && strings.Contains(line, ruleName) && strings.Contains(line, "drop") {
			return true, nil
		}
		// 也检查带 /32 后缀的情况
		if strings.Contains(line, "source address=\""+ip+"/32\"") && strings.Contains(line, ruleName) && strings.Contains(line, "drop") {
			return true, nil
		}
	}

	return false, nil
}

// isIPInRulesIptables 通过 iptables-save 检查 IP 是否已被封禁
func (fw *FireWallEngine) isIPInRulesIptables(ip string) (bool, error) {
	path, err := findExecutable("iptables-save")
	if err != nil {
		fmt.Printf("[ERROR] 获取iptables规则失败: %v\n", err)
		return false, fmt.Errorf("failed to find iptables-save: %v", err)
	}
	cmd := exec.Command(path)
	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("[ERROR] 获取iptables规则失败: %v\n", err)
		return false, fmt.Errorf("failed to list iptables rules: %v, output: %s", err, string(output))
	}
	outputStr := string(output)
	exists := strings.Contains(outputStr, "-A INPUT -s "+ip+" -j DROP") ||
		strings.Contains(outputStr, "-A INPUT -s "+ip+"/32 -j DROP")
	return exists, nil
}

// isIPInRules 检查IP是否在封禁规则中（自动选择后端）
func (fw *FireWallEngine) isIPInRules(ip string) (bool, error) {
	backend := getFirewallBackend()
	if backend == "firewalld" {
		return fw.isIPInRulesFirewalld(ip)
	}
	return fw.isIPInRulesIptables(ip)
}

// generateRuleName 生成规则名称
func generateRuleName(ip string) string {
	safeName := strings.ReplaceAll(ip, ".", "_")
	safeName = strings.ReplaceAll(safeName, "/", "_")
	return RULE_PREFIX + safeName
}

// AddRule Linux 下添加防火墙封禁规则（自动选择后端）
func (fw *FireWallEngine) AddRule(ruleName, ipToAdd, action, proc, localport string) error {
	backend := getFirewallBackend()
	if backend == "firewalld" {
		return fw.addRuleFirewalld(ruleName, ipToAdd, action, proc, localport)
	}
	return fw.addRuleIptables(ipToAdd)
}

// addRuleFirewalld 通过 firewall-cmd 添加封禁规则
func (fw *FireWallEngine) addRuleFirewalld(ruleName, ipToAdd, action, proc, localport string) error {
	path, err := findExecutable("firewall-cmd")
	if err != nil {
		return fmt.Errorf("failed to find firewall-cmd: %v", err)
	}

	// 构建 rich rule: rule priority="10" source address="IP" name="SamWAF_Block_x_x_x_x" drop
	richRule := fmt.Sprintf("rule priority=\"%s\" source address=\"%s\" name=\"%s\" drop",
		FIREWALLD_RICH_RULE_PRIORITY, ipToAdd, ruleName)

	// 添加永久规则 + 运行时规则
	cmd := exec.Command(path, "--add-rich-rule", richRule)
	fmt.Printf("[DEBUG] 执行命令: firewall-cmd --add-rich-rule '%s'\n", richRule)
	err2, output := fw.executeCommand(cmd)
	if err2 != nil {
		fmt.Printf("[ERROR] 添加运行时规则失败: %v, 输出: %s\n", err2, output)
		return fmt.Errorf("failed to add firewalld runtime rule: %v, output: %s", err2, output)
	}

	// 添加永久规则（确保重启后规则仍然生效）
	cmd = exec.Command(path, "--permanent", "--add-rich-rule", richRule)
	fmt.Printf("[DEBUG] 执行命令: firewall-cmd --permanent --add-rich-rule '%s'\n", richRule)
	err2, output = fw.executeCommand(cmd)
	if err2 != nil {
		fmt.Printf("[WARN] 添加永久规则失败: %v, 输出: %s (运行时规则已生效)\n", err2, output)
		// 运行时规则已生效，永久规则失败不算致命错误，仅警告
	}

	fmt.Printf("[DEBUG] 添加规则成功\n")
	return nil
}

// addRuleIptables 通过 iptables 添加封禁规则
func (fw *FireWallEngine) addRuleIptables(ipToAdd string) error {
	path, err := findExecutable("iptables")
	if err != nil {
		return fmt.Errorf("failed to find iptables: %v", err)
	}
	cmd := exec.Command(path, "-I", "INPUT", "1", "-s", ipToAdd, "-j", "DROP")
	fmt.Printf("[DEBUG] 执行命令: iptables -I INPUT 1 -s %s -j DROP\n", ipToAdd)
	err, output := fw.executeCommand(cmd)
	if err != nil {
		fmt.Printf("[ERROR] 添加规则失败: %v, 输出: %s\n", err, output)
		return fmt.Errorf("failed to add rule for %s: %v, output: %s", ipToAdd, err, output)
	}
	fmt.Printf("[DEBUG] 添加规则成功, 输出: %s\n", output)
	return nil
}

func (fw *FireWallEngine) EditRule(ruleNum int, newRule string) error {
	return fmt.Errorf("editRule is not supported on Linux")
}

// DeleteRule 删除防火墙规则（自动选择后端）
func (fw *FireWallEngine) DeleteRule(ruleName string) (bool, error) {
	backend := getFirewallBackend()
	if backend == "firewalld" {
		return fw.deleteRuleFirewalld(ruleName)
	}
	return fw.deleteRuleIptables(ruleName)
}

// deleteRuleFirewalld 通过 firewall-cmd 删除封禁规则
func (fw *FireWallEngine) deleteRuleFirewalld(ruleName string) (bool, error) {
	path, err := findExecutable("firewall-cmd")
	if err != nil {
		return false, fmt.Errorf("failed to find firewall-cmd: %v", err)
	}

	// 先查找包含该规则名的精确 rich rule（避免 CIDR 还原不准的问题）
	richRule, err := fw.findRichRuleByName(path, ruleName)
	if err != nil {
		return false, fmt.Errorf("failed to find rich rule for %s: %v", ruleName, err)
	}
	if richRule == "" {
		fmt.Printf("[WARN] 规则不存在: %s\n", ruleName)
		return false, nil
	}

	// 删除运行时规则
	cmd := exec.Command(path, "--remove-rich-rule", richRule)
	fmt.Printf("[DEBUG] 执行命令: firewall-cmd --remove-rich-rule '%s'\n", richRule)
	err2, output := fw.executeCommand(cmd)
	if err2 != nil {
		fmt.Printf("[ERROR] 删除运行时规则失败: %v, 输出: %s\n", err2, output)
		return false, fmt.Errorf("failed to remove firewalld runtime rule: %v, output: %s", err2, output)
	}

	// 删除永久规则
	cmd = exec.Command(path, "--permanent", "--remove-rich-rule", richRule)
	fmt.Printf("[DEBUG] 执行命令: firewall-cmd --permanent --remove-rich-rule '%s'\n", richRule)
	err2, output = fw.executeCommand(cmd)
	if err2 != nil {
		fmt.Printf("[WARN] 删除永久规则失败: %v, 输出: %s\n", err2, output)
	}

	fmt.Printf("[DEBUG] 删除规则成功\n")
	return true, nil
}

// findRichRuleByName 通过规则名查找精确的 rich rule 字符串
func (fw *FireWallEngine) findRichRuleByName(firewallCmdPath string, ruleName string) (string, error) {
	cmd := exec.Command(firewallCmdPath, "--list-rich-rules")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("failed to list rich rules: %v", err)
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "name=\""+ruleName+"\"") {
			return line, nil
		}
	}
	return "", nil
}

// deleteRuleIptables 通过 iptables 删除封禁规则
func (fw *FireWallEngine) deleteRuleIptables(ruleName string) (bool, error) {
	path, err := findExecutable("iptables")
	if err != nil {
		return false, fmt.Errorf("failed to find iptables: %v", err)
	}
	cmd := exec.Command(path, "-D", "INPUT", "-s", ruleName, "-j", "DROP")
	fmt.Printf("[DEBUG] 执行命令: iptables -D INPUT -s %s -j DROP\n", ruleName)
	err, output := fw.executeCommand(cmd)
	if err != nil {
		fmt.Printf("[ERROR] 删除规则失败: %v, 输出: %s\n", err, output)
		return false, fmt.Errorf("failed to delete rule for %s: %v, output: %s", ruleName, err, output)
	}
	fmt.Printf("[DEBUG] 删除规则成功\n")
	return true, nil
}

// extractIPFromRuleName 从规则名中提取IP
// generateRuleName 将 "." -> "_" 且 "/" -> "_"
// SamWAF_Block_192_168_1_100   => 192.168.1.100
// SamWAF_Block_192_168_1_0_24  => 192.168.1.0/24
// SamWAF_Block_10_0_0_1_32     => 10.0.0.1/32 (CIDR)  vs  10.0.0.132 (IP)
// 无法仅从规则名区分以上两种情况，因此使用 / 替换 _，然后让 firewall-cmd 来判断
// 实际上我们在删除/查询时不依赖 extractIPFromRuleName，而是直接用 firewall-cmd --list-rich-rules 查询
func extractIPFromRuleName(ruleName string) string {
	if !strings.HasPrefix(ruleName, RULE_PREFIX) {
		return ""
	}
	safeName := strings.TrimPrefix(ruleName, RULE_PREFIX)
	// 将 _ 还原为 .（IP 的点号）
	// 注意: / 也被替换为 _，但这里简单还原为 .
	// 在实际删除规则时，我们通过 --list-rich-rules 获取精确的 source address
	return strings.ReplaceAll(safeName, "_", ".")
}

// IsRuleExists 检查规则是否存在（自动选择后端）
func (fw *FireWallEngine) IsRuleExists(ruleName string) (bool, error) {
	backend := getFirewallBackend()
	if backend == "firewalld" {
		ip := extractIPFromRuleName(ruleName)
		if ip == "" {
			ip = ruleName
		}
		return fw.isIPInRulesFirewalld(ip)
	}
	return fw.isIPInRulesIptables(ruleName)
}

// BlockIP 封禁指定IP地址，支持单个IP或CIDR格式
func (fw *FireWallEngine) BlockIP(ip string, reason string) error {
	fmt.Printf("[INFO] 开始封禁IP: %s, 原因: %s\n", ip, reason)

	backend := getFirewallBackend()

	// 检查规则是否已存在
	exists, err := fw.isIPInRules(ip)
	if err != nil {
		return fmt.Errorf("检查IP状态失败: %v", err)
	}
	if exists {
		fmt.Printf("[WARN] IP %s 已经被封禁\n", ip)
		return fmt.Errorf("IP %s already blocked", ip)
	}

	ruleName := generateRuleName(ip)

	if backend == "firewalld" {
		err = fw.addRuleFirewalld(ruleName, ip, ACTION_BLOCK, PROTOCOL_ANY, "")
	} else {
		err = fw.addRuleIptables(ip)
	}

	if err != nil {
		fmt.Printf("[ERROR] 封禁IP失败: %s, error: %v\n", ip, err)
		return fmt.Errorf("failed to block IP %s: %v", ip, err)
	}

	fmt.Printf("[INFO] 成功封禁IP: %s\n", ip)
	return nil
}

// UnblockIP 解除对指定IP的封禁，支持单个IP或CIDR格式
func (fw *FireWallEngine) UnblockIP(ip string) error {
	fmt.Printf("[INFO] 开始解除IP封禁: %s\n", ip)

	// 检查规则是否存在
	exists, err := fw.isIPInRules(ip)
	if err != nil {
		return fmt.Errorf("检查IP状态失败: %v", err)
	}
	if !exists {
		fmt.Printf("[WARN] IP %s 未被封禁\n", ip)
		return fmt.Errorf("IP %s is not blocked", ip)
	}

	ruleName := generateRuleName(ip)
	backend := getFirewallBackend()

	if backend == "firewalld" {
		_, err = fw.deleteRuleFirewalld(ruleName)
	} else {
		_, err = fw.deleteRuleIptables(ip)
	}

	if err != nil {
		fmt.Printf("[ERROR] 解除IP封禁失败: %s, error: %v\n", ip, err)
		return fmt.Errorf("failed to unblock IP %s: %v", ip, err)
	}

	fmt.Printf("[INFO] 成功解除IP封禁: %s\n", ip)
	return nil
}

// IsIPBlocked 检查IP是否已被封禁
func (fw *FireWallEngine) IsIPBlocked(ip string) (bool, error) {
	fmt.Printf("[DEBUG] 检查IP是否被封禁: %s\n", ip)
	blocked, err := fw.isIPInRules(ip)
	if blocked {
		fmt.Printf("[DEBUG] IP %s 已被封禁\n", ip)
	} else {
		fmt.Printf("[DEBUG] IP %s 未被封禁\n", ip)
	}
	return blocked, err
}

// BlockIPList 批量封禁IP列表
func (fw *FireWallEngine) BlockIPList(ips []string) (successCount int, failedIPs []string, err error) {
	failedIPs = []string{}
	for _, ip := range ips {
		if e := fw.BlockIP(ip, ""); e != nil {
			failedIPs = append(failedIPs, ip)
		} else {
			successCount++
		}
	}
	if len(failedIPs) > 0 {
		return successCount, failedIPs, fmt.Errorf("failed to block %d IPs", len(failedIPs))
	}
	return successCount, failedIPs, nil
}

// UnblockIPList 批量解除IP封禁
func (fw *FireWallEngine) UnblockIPList(ips []string) (successCount int, failedIPs []string, err error) {
	failedIPs = []string{}
	for _, ip := range ips {
		if e := fw.UnblockIP(ip); e != nil {
			failedIPs = append(failedIPs, ip)
		} else {
			successCount++
		}
	}
	if len(failedIPs) > 0 {
		return successCount, failedIPs, fmt.Errorf("failed to unblock %d IPs", len(failedIPs))
	}
	return successCount, failedIPs, nil
}

// GetBlockedIPListFirewalld 通过 firewalld 获取已封禁IP列表
func (fw *FireWallEngine) GetBlockedIPListFirewalld() ([]string, error) {
	path, err := findExecutable("firewall-cmd")
	if err != nil {
		return nil, fmt.Errorf("failed to find firewall-cmd: %v", err)
	}

	// 使用 --list-rich-rules 获取所有 rich rules（每条一行，格式明确）
	cmd := exec.Command(path, "--list-rich-rules")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to list firewalld rich rules: %v", err)
	}

	blockedIPs := []string{}
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		// 只处理包含 SamWAF_Block_ 前缀的 rich rule
		if !strings.Contains(line, RULE_PREFIX) {
			continue
		}
		// 提取 source address="IP"
		addrStart := strings.Index(line, "source address=\"")
		if addrStart == -1 {
			continue
		}
		addrStart += len("source address=\"")
		addrEnd := strings.Index(line[addrStart:], "\"")
		if addrEnd == -1 {
			continue
		}
		ip := line[addrStart : addrStart+addrEnd]
		// 去掉 /32 后缀还原原始IP格式；CIDR 不受影响
		ip = strings.TrimSuffix(ip, "/32")
		if ip != "" {
			blockedIPs = append(blockedIPs, ip)
		}
	}
	return blockedIPs, nil
}

// GetBlockedIPListIptables 通过 iptables-save 获取已封禁IP列表
func (fw *FireWallEngine) GetBlockedIPListIptables() ([]string, error) {
	path, err := findExecutable("iptables-save")
	if err != nil {
		return nil, fmt.Errorf("failed to find iptables-save: %v", err)
	}
	cmd := exec.Command(path)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to get blocked IP list: %v", err)
	}

	blockedIPs := []string{}
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "-A INPUT -s") && strings.Contains(line, "-j DROP") {
			parts := strings.Fields(line)
			for i, part := range parts {
				if part == "-s" && i+1 < len(parts) {
					ip := parts[i+1]
					ip = strings.TrimSuffix(ip, "/32")
					blockedIPs = append(blockedIPs, ip)
					break
				}
			}
		}
	}
	return blockedIPs, nil
}

// GetBlockedIPList 获取所有已封禁的IP列表（自动选择后端）
func (fw *FireWallEngine) GetBlockedIPList() ([]string, error) {
	backend := getFirewallBackend()
	if backend == "firewalld" {
		return fw.GetBlockedIPListFirewalld()
	}
	return fw.GetBlockedIPListIptables()
}

// ClearAllBlockedIPs 清除所有封禁规则
func (fw *FireWallEngine) ClearAllBlockedIPs() (int, error) {
	blockedIPs, err := fw.GetBlockedIPList()
	if err != nil {
		return 0, err
	}
	count := 0
	for _, ip := range blockedIPs {
		if fw.UnblockIP(ip) == nil {
			count++
		}
	}
	return count, nil
}
