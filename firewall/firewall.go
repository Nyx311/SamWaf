//go:build linux

package firewall

import (
	"SamWaf/common/wafexec"
	"SamWaf/utils"
	"bufio"
	"fmt"
	"os"
	"os/exec"
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

// searchPaths 可执行文件搜索路径（容器和宿主机通用）
var searchPaths = []string{
	"/usr/sbin", "/sbin", "/usr/local/sbin",
	"/usr/bin", "/bin", "/usr/local/bin",
}

type FireWallEngine struct{}

// IPBlockInfo IP封禁信息结构
type IPBlockInfo struct {
	IP        string    // IP地址
	Reason    string    // 封禁原因
	BlockTime time.Time // 封禁时间
	Protocol  string    // 协议类型
	Direction string    // 方向
}

// findExecutable 在 PATH 和常见 sbin 目录中查找可执行文件
func findExecutable(name string) (string, error) {
	if path, err := exec.LookPath(name); err == nil {
		return path, nil
	}
	for _, dir := range searchPaths {
		fullPath := dir + "/" + name
		info, err := os.Stat(fullPath)
		if err == nil && !info.IsDir() && info.Mode()&0111 != 0 {
			return fullPath, nil
		}
	}
	return "", fmt.Errorf("executable %s not found in PATH or known directories", name)
}

// detectFirewallBackend 检测防火墙后端
func detectFirewallBackend() string {
	path, err := findExecutable("firewall-cmd")
	if err == nil {
		output, err := exec.Command(path, "--state").CombinedOutput()
		if err == nil && strings.TrimSpace(string(output)) == "running" {
			return "firewalld"
		}
	}
	return "iptables"
}

var cachedBackend string

func getFirewallBackend() string {
	if cachedBackend == "" {
		cachedBackend = detectFirewallBackend()
		fmt.Printf("[INFO] 检测到防火墙后端: %s\n", cachedBackend)
	}
	return cachedBackend
}

func (fw *FireWallEngine) IsFirewallEnabled() bool {
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
	path, err := findExecutable("iptables")
	if err != nil {
		return false
	}
	out, err := wafexec.FixStdin(exec.Command(path, "-L")).CombinedOutput()
	if err != nil {
		return false
	}
	return len(out) > 0
}

// containerHint 容器部署时的补充说明
const containerHint = "当前运行在容器内：镜像中需安装 iptables（alpine: apk add iptables），" +
	"并以 --cap-add=NET_ADMIN --network host 启动容器，否则规则只写入容器自身的网络命名空间，对宿主机流量无效。"

// isInContainer 判断当前进程是否运行在容器内。
// 统一走 utils.DetectContainerRuntime（与"系统信息"弹窗展示的运行环境、升级拦截用的是同一处判定），
// 避免同一套 /.dockerenv + cgroup 规则在仓库里散落多份、各自演进。
func isInContainer() bool {
	return utils.DetectContainerRuntime() != ""
}

// checkAvailable 探测 iptables 是否存在且当前进程有权限操作，供 CheckAvailable 带缓存调用
func (fw *FireWallEngine) checkAvailable() error {
	for _, bin := range []string{"iptables", "iptables-save"} {
		if _, err := exec.LookPath(bin); err != nil {
			msg := fmt.Sprintf("当前环境未安装 %s，无法使用系统防火墙封禁，可改用 WAF 应用层 IP 黑名单。", bin)
			if isInContainer() {
				msg += containerHint
			}
			return fmt.Errorf("%s", msg)
		}
	}

	out, err := wafexec.FixStdin(exec.Command("iptables", "-S", "INPUT")).CombinedOutput()
	if err != nil {
		output := strings.TrimSpace(string(out))
		if strings.Contains(output, "Permission denied") ||
			strings.Contains(output, "must be root") ||
			strings.Contains(output, "Operation not permitted") {
			msg := "当前进程没有操作 iptables 的权限，请以 root 身份运行。"
			if isInContainer() {
				msg += containerHint
			}
			return fmt.Errorf("%s原始信息: %s", msg, output)
		}
		return fmt.Errorf("iptables 不可用: %v, 输出: %s", err, output)
	}

	return nil
}

func (fw *FireWallEngine) executeCommand(cmd *exec.Cmd) (error, string) {
	// 只补 Stdin：下面要取 StdoutPipe/StderrPipe，Stdout/Stderr 必须留给 os/exec 自己接管
	wafexec.FixStdin(cmd)
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
	cmd := exec.Command(path, "--list-rich-rules")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return false, fmt.Errorf("failed to list firewalld rich rules: %v", err)
	}
	outputStr := string(output)
	ruleName := generateRuleName(ip)
	lines := strings.Split(outputStr, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "source address=\""+ip+"\"") && strings.Contains(line, ruleName) && strings.Contains(line, "drop") {
			return true, nil
		}
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
	cmd := wafexec.FixStdin(exec.Command(path))
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

func (fw *FireWallEngine) isIPInRules(ip string) (bool, error) {
	if getFirewallBackend() == "firewalld" {
		return fw.isIPInRulesFirewalld(ip)
	}
	return fw.isIPInRulesIptables(ip)
}

func generateRuleName(ip string) string {
	safeName := strings.ReplaceAll(ip, ".", "_")
	safeName = strings.ReplaceAll(safeName, "/", "_")
	return RULE_PREFIX + safeName
}

func (fw *FireWallEngine) AddRule(ruleName, ipToAdd, action, proc, localport string) error {
	if getFirewallBackend() == "firewalld" {
		return fw.addRuleFirewalld(ruleName, ipToAdd, action, proc, localport)
	}
	return fw.addRuleIptables(ipToAdd)
}

func (fw *FireWallEngine) addRuleFirewalld(ruleName, ipToAdd, action, proc, localport string) error {
	path, err := findExecutable("firewall-cmd")
	if err != nil {
		return fmt.Errorf("failed to find firewall-cmd: %v", err)
	}
	richRule := fmt.Sprintf("rule priority=\"%s\" source address=\"%s\" name=\"%s\" drop",
		FIREWALLD_RICH_RULE_PRIORITY, ipToAdd, ruleName)
	cmd := exec.Command(path, "--add-rich-rule", richRule)
	fmt.Printf("[DEBUG] 执行命令: firewall-cmd --add-rich-rule '%s'\n", richRule)
	err2, output := fw.executeCommand(cmd)
	if err2 != nil {
		fmt.Printf("[ERROR] 添加运行时规则失败: %v, 输出: %s\n", err2, output)
		return fmt.Errorf("failed to add firewalld runtime rule: %v, output: %s", err2, output)
	}
	cmd = exec.Command(path, "--permanent", "--add-rich-rule", richRule)
	fmt.Printf("[DEBUG] 执行命令: firewall-cmd --permanent --add-rich-rule '%s'\n", richRule)
	err2, output = fw.executeCommand(cmd)
	if err2 != nil {
		fmt.Printf("[WARN] 添加永久规则失败: %v, 输出: %s (运行时规则已生效)\n", err2, output)
	}
	fmt.Printf("[DEBUG] 添加规则成功\n")
	return nil
}

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

func (fw *FireWallEngine) DeleteRule(ruleName string) (bool, error) {
	if getFirewallBackend() == "firewalld" {
		return fw.deleteRuleFirewalld(ruleName)
	}
	return fw.deleteRuleIptables(ruleName)
}

func (fw *FireWallEngine) deleteRuleFirewalld(ruleName string) (bool, error) {
	richRule, err := fw.findRichRuleByName(ruleName)
	if err != nil {
		return false, fmt.Errorf("failed to find rich rule for %s: %v", ruleName, err)
	}
	if richRule == "" {
		fmt.Printf("[WARN] 规则不存在: %s\n", ruleName)
		return false, nil
	}
	path, err := findExecutable("firewall-cmd")
	if err != nil {
		return false, fmt.Errorf("failed to find firewall-cmd: %v", err)
	}
	cmd := exec.Command(path, "--remove-rich-rule", richRule)
	fmt.Printf("[DEBUG] 执行命令: firewall-cmd --remove-rich-rule '%s'\n", richRule)
	err2, output := fw.executeCommand(cmd)
	if err2 != nil {
		fmt.Printf("[ERROR] 删除运行时规则失败: %v, 输出: %s\n", err2, output)
		return false, fmt.Errorf("failed to remove firewalld runtime rule: %v, output: %s", err2, output)
	}
	cmd = exec.Command(path, "--permanent", "--remove-rich-rule", richRule)
	fmt.Printf("[DEBUG] 执行命令: firewall-cmd --permanent --remove-rich-rule '%s'\n", richRule)
	err2, output = fw.executeCommand(cmd)
	if err2 != nil {
		fmt.Printf("[WARN] 删除永久规则失败: %v, 输出: %s\n", err2, output)
	}
	fmt.Printf("[DEBUG] 删除规则成功\n")
	return true, nil
}

func (fw *FireWallEngine) findRichRuleByName(ruleName string) (string, error) {
	path, err := findExecutable("firewall-cmd")
	if err != nil {
		return "", fmt.Errorf("failed to find firewall-cmd: %v", err)
	}
	cmd := exec.Command(path, "--list-rich-rules")
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

func extractIPFromRuleName(ruleName string) string {
	if !strings.HasPrefix(ruleName, RULE_PREFIX) {
		return ""
	}
	safeName := strings.TrimPrefix(ruleName, RULE_PREFIX)
	return strings.ReplaceAll(safeName, "_", ".")
}

func (fw *FireWallEngine) IsRuleExists(ruleName string) (bool, error) {
	if getFirewallBackend() == "firewalld" {
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
	exists, err := fw.isIPInRules(ip)
	if err != nil {
		return fmt.Errorf("检查IP状态失败: %v", err)
	}
	if exists {
		fmt.Printf("[WARN] IP %s 已经被封禁\n", ip)
		return fmt.Errorf("IP %s already blocked", ip)
	}
	ruleName := generateRuleName(ip)
	if getFirewallBackend() == "firewalld" {
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

// UnblockIP 解除对指定IP的封禁
func (fw *FireWallEngine) UnblockIP(ip string) error {
	fmt.Printf("[INFO] 开始解除IP封禁: %s\n", ip)
	exists, err := fw.isIPInRules(ip)
	if err != nil {
		return fmt.Errorf("检查IP状态失败: %v", err)
	}
	if !exists {
		fmt.Printf("[WARN] IP %s 未被封禁\n", ip)
		return fmt.Errorf("IP %s is not blocked", ip)
	}
	ruleName := generateRuleName(ip)
	if getFirewallBackend() == "firewalld" {
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

func (fw *FireWallEngine) GetBlockedIPListFirewalld() ([]string, error) {
	path, err := findExecutable("firewall-cmd")
	if err != nil {
		return nil, fmt.Errorf("failed to find firewall-cmd: %v", err)
	}
	cmd := exec.Command(path, "--list-rich-rules")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to list firewalld rich rules: %v", err)
	}
	blockedIPs := []string{}
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if !strings.Contains(line, RULE_PREFIX) {
			continue
		}
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
		ip = strings.TrimSuffix(ip, "/32")
		if ip != "" {
			blockedIPs = append(blockedIPs, ip)
		}
	}
	return blockedIPs, nil
}

func (fw *FireWallEngine) GetBlockedIPListIptables() ([]string, error) {
	path, err := findExecutable("iptables-save")
	if err != nil {
		return nil, fmt.Errorf("failed to find iptables-save: %v", err)
	}
	cmd := wafexec.FixStdin(exec.Command(path))
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

func (fw *FireWallEngine) GetBlockedIPList() ([]string, error) {
	if getFirewallBackend() == "firewalld" {
		return fw.GetBlockedIPListFirewalld()
	}
	return fw.GetBlockedIPListIptables()
}

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
