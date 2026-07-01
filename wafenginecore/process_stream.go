package wafenginecore

import (
	"SamWaf/common/uuid"
	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/model"
	"SamWaf/utils"
	"io"
	"strings"
	"time"
)

// StreamProcessor 流式内容处理器
type StreamProcessor struct {
	originalReader io.ReadCloser
	wafEngine      *WafEngine
	wafContext     innerbean.WafHttpContextData
	hostCode       string
	buffer         []byte // 原始流中尚未按\n分割完毕的数据
	resultBuffer   []byte // 已处理完毕、等待填入Read()调用方p[]的数据
	eofReceived    bool   // 标记originalReader是否已返回EOF
}

// 创建流式处理器
func (waf *WafEngine) createStreamProcessor(originalBody io.ReadCloser, wafContext innerbean.WafHttpContextData, hostCode string) *StreamProcessor {
	return &StreamProcessor{
		originalReader: originalBody,
		wafEngine:      waf,
		wafContext:     wafContext,
		hostCode:       hostCode,
		buffer:         make([]byte, 0, 4096),
		resultBuffer:   make([]byte, 0, 4096),
		eofReceived:    false,
	}
}

// Read 实现io.Reader接口
func (sp *StreamProcessor) Read(p []byte) (n int, err error) {
	// Step 1: resultBuffer有数据时优先从中填满p，不读原始流
	if len(sp.resultBuffer) > 0 {
		copyLen := len(sp.resultBuffer)
		if copyLen > len(p) {
			copyLen = len(p)
		}
		copy(p, sp.resultBuffer[:copyLen])
		sp.resultBuffer = sp.resultBuffer[copyLen:]

		// resultBuffer耗尽后重新分配，避免底层数组无限增长
		if len(sp.resultBuffer) == 0 {
			sp.resultBuffer = make([]byte, 0, 4096)
		}

		// EOF仅在resultBuffer完全耗尽且原始流已EOF时才返回
		if len(sp.resultBuffer) == 0 && sp.eofReceived {
			return copyLen, io.EOF
		}
		return copyLen, nil
	}

	// Step 2: resultBuffer空，从原始流读取数据到buffer
	tempBuf := make([]byte, len(p)+4096)
	readN, readErr := sp.originalReader.Read(tempBuf)
	if readN > 0 {
		sp.buffer = append(sp.buffer, tempBuf[:readN]...)
	}
	if readErr == io.EOF {
		sp.eofReceived = true
		readErr = nil // 不立即传播EOF，可能还有数据需要处理
	} else if readErr != nil {
		// 非EOF错误：先处理已积累的数据，再传播错误
		sp.processAndFillResultBuffer()
		if len(sp.resultBuffer) > 0 {
			copyLen := len(sp.resultBuffer)
			if copyLen > len(p) {
				copyLen = len(p)
			}
			copy(p, sp.resultBuffer[:copyLen])
			sp.resultBuffer = sp.resultBuffer[copyLen:]
			return copyLen, readErr
		}
		return 0, readErr
	}

	// Step 3: 处理buffer中的原始数据，结果存入resultBuffer
	sp.processAndFillResultBuffer()

	// Step 4: 从resultBuffer填满p
	if len(sp.resultBuffer) > 0 {
		copyLen := len(sp.resultBuffer)
		if copyLen > len(p) {
			copyLen = len(p)
		}
		copy(p, sp.resultBuffer[:copyLen])
		sp.resultBuffer = sp.resultBuffer[copyLen:]
		if len(sp.resultBuffer) == 0 {
			sp.resultBuffer = make([]byte, 0, 4096)
		}
		return copyLen, nil
	}

	// Step 5: resultBuffer空且原始流已EOF
	if sp.eofReceived {
		return 0, io.EOF
	}
	return 0, nil
}

// Close 实现io.Closer接口
func (sp *StreamProcessor) Close() error {
	if sp.originalReader != nil {
		return sp.originalReader.Close()
	}
	return nil
}

// 处理buffer中的原始流数据，结果存入resultBuffer
func (sp *StreamProcessor) processAndFillResultBuffer() {
	if len(sp.buffer) == 0 {
		return
	}

	data := string(sp.buffer)

	// 判断buffer是否以\n结尾，区分完整空行（SSE事件边界）和不完整行
	endsWithNewline := len(data) > 0 && data[len(data)-1] == '\n'

	lines := strings.Split(data, "\n")

	var processedLines []string

	if endsWithNewline {
		// 所有分割片段都是完整行（含空行事件边界）
		// Split("data: hello\n\n", "\n") => ["data: hello", "", ""]
		// 最后一个""是\n末尾的artifact，倒数第二个""是事件边界空行
		// 处理 lines[0..len-2] 作为完整行，最后的空串artifact跳过
		completeLineCount := len(lines) - 1
		for i := 0; i < completeLineCount; i++ {
			processedLine := sp.processLine(lines[i])
			processedLines = append(processedLines, processedLine)
		}
		// buffer完全消耗，重新分配
		sp.buffer = make([]byte, 0, 4096)
	} else {
		// 不以\n结尾：最后一片段是不完整行，保留在buffer
		if len(lines) <= 1 {
			// 没有任何\n，整段都不完整，不处理
			return
		}
		for i := 0; i < len(lines)-1; i++ {
			processedLine := sp.processLine(lines[i])
			processedLines = append(processedLines, processedLine)
		}
		sp.buffer = []byte(lines[len(lines)-1])
	}

	// 拼接已处理的完整行，每行末尾恢复\n（因为它们原本是\n终止的）
	if len(processedLines) > 0 {
		result := strings.Join(processedLines, "\n") + "\n"
		sp.resultBuffer = append(sp.resultBuffer, []byte(result)...)
	}
}

// 处理单行数据
func (sp *StreamProcessor) processLine(line string) string {
	// SSE空行（事件边界）原样透传
	if line == "" {
		return line
	}

	// data: 行：提取内容做隐私保护+敏感词处理
	if strings.HasPrefix(line, "data:") {
		// SSE规范：data:后如果有单个空格则剥离，否则保留
		eventData := line[5:]
		if len(eventData) > 0 && eventData[0] == ' ' {
			eventData = eventData[1:]
		}

		// 隐私保护处理
		eventData = sp.processPrivacyProtection(eventData)

		// 敏感词检测和替换（返回纯内容，不带data:前缀和\n）
		eventData = sp.processSensitiveWords(eventData)

		return "data: " + eventData
	}

	// event: / id: / retry: 行原样透传，不修改协议字段
	if strings.HasPrefix(line, "event:") ||
		strings.HasPrefix(line, "id:") ||
		strings.HasPrefix(line, "retry:") {
		return line
	}

	// SSE注释行（以:开头）原样透传
	if strings.HasPrefix(line, ":") {
		return line
	}

	// 其他未知行原样透传
	return line
}

// 隐私保护处理
func (sp *StreamProcessor) processPrivacyProtection(data string) string {
	// 检查是否需要进行隐私保护
	host := sp.wafEngine.rt().HostCode[sp.wafContext.HostCode]
	lowerRequestURI := strings.ToLower(sp.wafContext.Weblog.URL)

	ldpFlag := false

	// 检查局部隐私保护规则
	for i := 0; i < len(sp.wafEngine.rt().HostTarget[host].LdpUrlLists); i++ {
		lowerRuleURL := strings.ToLower(sp.wafEngine.rt().HostTarget[host].LdpUrlLists[i].Url)

		if (sp.wafEngine.rt().HostTarget[host].LdpUrlLists[i].CompareType == "等于" && lowerRuleURL == lowerRequestURI) ||
			(sp.wafEngine.rt().HostTarget[host].LdpUrlLists[i].CompareType == "前缀匹配" && strings.HasPrefix(lowerRequestURI, lowerRuleURL)) ||
			(sp.wafEngine.rt().HostTarget[host].LdpUrlLists[i].CompareType == "后缀匹配" && strings.HasSuffix(lowerRequestURI, lowerRuleURL)) ||
			(sp.wafEngine.rt().HostTarget[host].LdpUrlLists[i].CompareType == "包含匹配" && strings.Contains(lowerRequestURI, lowerRuleURL)) {
			ldpFlag = true
			break
		}
	}

	// 检查全局隐私保护规则
	if !ldpFlag {
		for i := 0; i < len(sp.wafEngine.rt().HostTarget[global.GWAF_GLOBAL_HOST_NAME].LdpUrlLists); i++ {
			lowerGlobalRuleURL := strings.ToLower(sp.wafEngine.rt().HostTarget[global.GWAF_GLOBAL_HOST_NAME].LdpUrlLists[i].Url)

			if (sp.wafEngine.rt().HostTarget[global.GWAF_GLOBAL_HOST_NAME].LdpUrlLists[i].CompareType == "等于" && lowerGlobalRuleURL == lowerRequestURI) ||
				(sp.wafEngine.rt().HostTarget[global.GWAF_GLOBAL_HOST_NAME].LdpUrlLists[i].CompareType == "前缀匹配" && strings.HasPrefix(lowerRequestURI, lowerGlobalRuleURL)) ||
				(sp.wafEngine.rt().HostTarget[global.GWAF_GLOBAL_HOST_NAME].LdpUrlLists[i].CompareType == "后缀匹配" && strings.HasSuffix(lowerRequestURI, lowerGlobalRuleURL)) ||
				(sp.wafEngine.rt().HostTarget[global.GWAF_GLOBAL_HOST_NAME].LdpUrlLists[i].CompareType == "包含匹配" && strings.Contains(lowerRequestURI, lowerGlobalRuleURL)) {
				ldpFlag = true
				break
			}
		}
	}

	// 如果需要隐私保护，进行脱敏处理
	if ldpFlag {
		return utils.DeSenText(data)
	}

	return data
}

// 敏感词检测和替换
func (sp *StreamProcessor) processSensitiveWords(data string) string {
	// 检查是否启用敏感词检测
	if !sp.wafEngine.CheckResponseSensitive() {
		return data
	}

	// 进行敏感词检测
	matchResult := sp.wafEngine.SensitiveManager.MultiPatternSearch([]rune(data), false)
	if len(matchResult) > 0 {
		processedData := data
		detectedWordsMap := make(map[string]bool) // 使用map去重
		var detectedWords []string
		var hasDenyAction bool

		for _, match := range matchResult {
			sensitive := match.CustomData.(model.Sensitive)
			word := string(match.Word)

			if sensitive.CheckDirection != "in" {
				// 检查是否已经存在，避免重复添加
				if !detectedWordsMap[word] {
					detectedWordsMap[word] = true
					detectedWords = append(detectedWords, word)
				}

				if sensitive.Action == "deny" {
					hasDenyAction = true
				} else {
					// 替换敏感词
					processedData = strings.ReplaceAll(processedData, word, global.GWAF_HTTP_SENSITIVE_REPLACE_STRING)
				}
			}
		}

		// 统一记录一次日志，避免重复记录
		if len(detectedWords) > 0 {
			if hasDenyAction {
				sp.logSensitiveDetection(detectedWords, "deny", data)
				// deny动作返回纯文本屏蔽信息，让processLine负责重组SSE格式
				return "[敏感内容已屏蔽]"
			} else {
				sp.logSensitiveDetection(detectedWords, "replace", data)
			}
		}

		return processedData
	}

	return data
}

// 记录敏感词检测日志
func (sp *StreamProcessor) logSensitiveDetection(words []string, action string, data string) {
	datetimeNow := time.Now()
	logEntry := *sp.wafContext.Weblog // 先拷贝，避免修改原始Weblog
	logEntry.REQ_UUID = uuid.GenUUID()
	logEntry.RISK_LEVEL = 1
	logEntry.GUEST_IDENTIFICATION = "触发敏感词"
	logEntry.RULE = "敏感词检测：" + strings.Join(words, ",")
	logEntry.CREATE_TIME = datetimeNow.Format("2006-01-02 15:04:05")
	logEntry.UNIX_ADD_TIME = datetimeNow.UnixNano() / 1e6
	logEntry.RES_BODY = data

	if action == "deny" {
		logEntry.ACTION = "阻止"
	} else {
		logEntry.ACTION = "放行"
	}

	// 异步记录日志，避免阻塞流处理
	go func() {
		global.GQEQUE_LOG_DB.Enqueue(logEntry)
	}()
}
