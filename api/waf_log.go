package api

import (
	"SamWaf/common/zlog"
	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/model/common/response"
	"SamWaf/model/request"
	response2 "SamWaf/model/response"
	"SamWaf/utils"
	"SamWaf/wafdb"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

type WafLogAPi struct {
}

// GetDetailApi 鑾峰彇鏀诲嚮鏃ュ織璇︽儏
// @Summary      鑾峰彇鏀诲嚮鏃ュ織璇︽儏
// @Description  鏍规嵁 req_uuid 鑾峰彇鍗曟潯鏀诲嚮鏃ュ織璇︽儏锛堝惈璇锋眰浣撱€佸搷搴斾綋锛?
// @Tags         鏃ュ織-鏀诲嚮鏃ュ織
// @Accept       json
// @Produce      json
// @Param        req_uuid         query  string  true   "璇锋眰UUID"
// @Param        current_db_name  query  string  false  "鏁版嵁搴撳悕绉帮紝榛樿 local_log"
// @Param        output_format    query  string  false  "杈撳嚭鏍煎紡锛歳aw 鎴?curl"
// @Success      200  {object}  response.Response  "鑾峰彇鎴愬姛"
// @Security     ApiKeyAuth
// @Router       /waflog/attack/detail [get]
func (w *WafLogAPi) GetDetailApi(c *gin.Context) {
	var req request.WafAttackLogDetailReq
	err := c.ShouldBind(&req)
	if err == nil {
		if global.GDATA_CURRENT_CHANGE {
			//濡傛灉姝ｅ湪鍒囨崲搴?璺宠繃
			response.FailWithMessage("姝ｅ湪鍒囨崲鏁版嵁搴撹绛夊緟", c)
			return
		}
		wafLog, _ := wafLogService.GetDetailApi(req)
		response.OkWithDetailed(wafLog, "鑾峰彇鎴愬姛", c)
	} else {
		response.FailWithMessage("瑙ｆ瀽澶辫触", c)
	}
}

// GetListApi 鑾峰彇鏀诲嚮鏃ュ織鍒楄〃
// @Summary      鑾峰彇鏀诲嚮鏃ュ織鍒楄〃
// @Description  鍒嗛〉鏌ヨ鏀诲嚮鏃ュ織锛屾敮鎸佹寜涓绘満鐮併€佽鍒欍€両P銆佹椂闂磋寖鍥寸瓑杩囨护
// @Tags         鏃ュ織-鏀诲嚮鏃ュ織
// @Accept       json
// @Produce      json
// @Param        data  body      request.WafAttackLogSearch  true  "鏌ヨ鍙傛暟"
// @Success      200   {object}  response.Response{data=response.PageResult}  "鑾峰彇鎴愬姛"
// @Security     ApiKeyAuth
// @Router       /waflog/attack/list [post]
func (w *WafLogAPi) GetListApi(c *gin.Context) {
	var req request.WafAttackLogSearch
	err := c.ShouldBindJSON(&req)
	if err == nil {
		zlog.Debug("WafLogAPI GetListApi req", "host_code", req.HostCode, "src_ip", req.SrcIp, "rule", req.Rule, "action", req.Action, "db", req.CurrrentDbName, "time_begin", req.UnixAddTimeBegin, "time_end", req.UnixAddTimeEnd, "page_index", req.PageIndex, "page_size", req.PageSize, "sort_by", req.SortBy, "sort_desc", req.SortDescending, "filter_by", req.FilterBy, "filter_value_len", len(req.FilterValue))
		if global.GDATA_CURRENT_CHANGE {
			//濡傛灉姝ｅ湪鍒囨崲搴?璺宠繃
			response.FailWithMessage("姝ｅ湪鍒囨崲鏁版嵁搴撹绛夊緟", c)
			return
		}
		wafLogs, total, err2 := wafLogService.GetListApi(req)
		if err2 != nil {
			zlog.Warn("WafLogAPI GetListApi failed", "err", err2.Error())
			response.FailWithMessage("璁块棶鍒楄〃澶辫触:"+err2.Error(), c)
		} else {
			zlog.Debug("WafLogAPI GetListApi ok", "rows", len(wafLogs), "total", total)
			response.OkWithDetailed(response.PageResult{
				List:      wafLogs,
				Total:     total,
				PageIndex: req.PageIndex,
				PageSize:  req.PageSize,
			}, "鑾峰彇鎴愬姛", c)
		}

	} else {
		response.FailWithMessage("瑙ｆ瀽澶辫触", c)
	}
}
func (w *WafLogAPi) ExportDBApi(c *gin.Context) {
	if global.GWAF_CAN_EXPORT_DOWNLOAD_LOG == false {
		// 浣跨敤鎿嶄綔缁撴灉娑堟伅鏍煎紡
		serverName := global.GWAF_CUSTOM_SERVER_NAME
		if serverName == "" {
			serverName = "鏈懡鍚嶆湇鍔″櫒"
		}
		global.GQEQUE_MESSAGE_DB.Enqueue(innerbean.OpResultMessageInfo{
			BaseMessageInfo: innerbean.BaseMessageInfo{
				OperaType: "瀵煎嚭澶辫触",
				Server:    serverName,
			},
			Msg:     "褰撳墠涓嶅厑璁稿鍑?,
			Success: "false",
		})
		response.FailWithMessage("褰撳墠涓嶅厑璁稿鍑?, c)
		return
	}
	if global.GDATA_CURRENT_CHANGE {
		//濡傛灉姝ｅ湪鍒囨崲搴?璺宠繃
		response.FailWithMessage("姝ｅ湪鍒囨崲鏁版嵁搴撹绛夊緟", c)
		return
	}
	//TODO 蹇呴』鍐嶉獙璇佷竴娆℃潈闄?
	//鏄惁鐢熸垚浜?杩樻病涓嬭浇
	if len(global.GWAF_RUNTIME_CURRENT_EXPORT_DB_LOG_FILE_PATH) > 0 {
		response.FailWithMessage("鏂囦欢杩樻湭涓嬭浇璇风瓑寰?, c)
		return
	}

	go func() {
		currentDir := utils.GetCurrentDir()
		downLoadDir := currentDir + "/download"
		// 鍒ゆ柇澶囦唤鐩綍鏄惁瀛樺湪锛屼笉瀛樺湪鍒欏垱寤?
		if _, err := os.Stat(downLoadDir); os.IsNotExist(err) {
			if err := os.MkdirAll(downLoadDir, os.ModePerm); err != nil {
				zlog.Error("鍒涘缓涓嬭浇鐩綍澶辫触:", err)
				return
			}
		}
		//澶勭悊鑰佹棫鏁版嵁
		duration := 30 * time.Minute
		utils.DeleteOldFiles(downLoadDir, duration)

		// 鍒涘缓涓嬭浇鏂囦欢
		downloadFileName := fmt.Sprintf("local_log_backup_%s.db", time.Now().Format("20060102150405"))
		downloadFilePath := filepath.Join(downLoadDir, downloadFileName)
		err := wafdb.BackupDatabase(global.GWAF_LOCAL_LOG_DB, downloadFilePath)
		if err != nil {
			global.GQEQUE_MESSAGE_DB.Enqueue(innerbean.OpResultMessageInfo{
				BaseMessageInfo: innerbean.BaseMessageInfo{OperaType: "DOWNLOAD_LOG", Server: global.GWAF_CUSTOM_SERVER_NAME},
				Msg:             "瀵煎嚭澶辫触",
				Success:         "true",
			})
		} else {
			global.GWAF_RUNTIME_CURRENT_EXPORT_DB_LOG_FILE_PATH = downloadFilePath
			//鍙戦€亀ebsocket 鎺ㄩ€佹秷鎭?
			global.GQEQUE_MESSAGE_DB.Enqueue(innerbean.ExportResultMessageInfo{
				BaseMessageInfo: innerbean.BaseMessageInfo{OperaType: "DOWNLOAD_LOG", Server: global.GWAF_CUSTOM_SERVER_NAME},
				Msg:             "瀵煎嚭瀹屾瘯",
				Success:         "true",
			})
		}
	}()
}
func (w *WafLogAPi) DownloadApi(c *gin.Context) {
	if global.GWAF_CAN_EXPORT_DOWNLOAD_LOG == false {
		// 浣跨敤鎿嶄綔缁撴灉娑堟伅鏍煎紡
		serverName := global.GWAF_CUSTOM_SERVER_NAME
		if serverName == "" {
			serverName = "鏈懡鍚嶆湇鍔″櫒"
		}
		global.GQEQUE_MESSAGE_DB.Enqueue(innerbean.OpResultMessageInfo{
			BaseMessageInfo: innerbean.BaseMessageInfo{
				OperaType: "涓嬭浇澶辫触",
				Server:    serverName,
			},
			Msg:     "褰撳墠涓嶅厑璁镐笅杞?,
			Success: "false",
		})
		c.JSON(http.StatusInternalServerError, gin.H{"message": "褰撳墠涓嶅厑璁镐笅杞?})
		return
	}
	if len(global.GWAF_RUNTIME_CURRENT_EXPORT_DB_LOG_FILE_PATH) == 0 {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to download file,not find file"})
		return
	}
	// 鎻愪緵鏂囦欢涓嬭浇
	c.FileAttachment(global.GWAF_RUNTIME_CURRENT_EXPORT_DB_LOG_FILE_PATH, "log.db")

	global.GWAF_RUNTIME_CURRENT_EXPORT_DB_LOG_FILE_PATH = ""
	// 涓嬭浇瀹屾垚鍚庡垹闄ゆ枃浠?
	err := os.Remove(global.GWAF_RUNTIME_CURRENT_EXPORT_DB_LOG_FILE_PATH)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to delete file"})
		return
	}
}
func (w *WafLogAPi) GetListByHostCodeApi(c *gin.Context) {
	var req request.WafAttackLogSearch
	err := c.ShouldBind(&req)
	if err == nil {
		if global.GDATA_CURRENT_CHANGE {
			//濡傛灉姝ｅ湪鍒囨崲搴?璺宠繃
			response.FailWithMessage("姝ｅ湪鍒囨崲鏁版嵁搴撹绛夊緟", c)
			return
		}
		wafLogs, total, _ := wafLogService.GetListByHostCodeApi(req)
		response.OkWithDetailed(response.PageResult{
			List:      wafLogs,
			Total:     total,
			PageIndex: req.PageIndex,
			PageSize:  req.PageSize,
		}, "鑾峰彇鎴愬姛", c)
	} else {
		response.FailWithMessage("瑙ｆ瀽澶辫触", c)
	}
}

func (w *WafLogAPi) GetAllShareDbApi(c *gin.Context) {
	wafShareList, _ := wafShareDbService.GetAllShareDbApi()
	allShareDbRep := make([]response2.AllShareDbRep, len(wafShareList)) // 鍒涘缓鏁扮粍
	for i, _ := range wafShareList {

		allShareDbRep[i] = response2.AllShareDbRep{
			StartTime: wafShareList[i].StartTime,
			EndTime:   wafShareList[i].EndTime,
			FileName:  wafShareList[i].FileName,
			Cnt:       wafShareList[i].Cnt,
		}

	}
	response.OkWithDetailed(allShareDbRep, "鑾峰彇鎴愬姛", c)
}

// http 鍘熷璇锋眰骞惰繘琛岃劚鏁忓鐞?
func (w *WafLogAPi) GetHttpCopyMaskApi(c *gin.Context) {
	var req request.WafAttackLogDetailReq
	err := c.ShouldBind(&req)
	if err == nil {
		if global.GDATA_CURRENT_CHANGE {
			//濡傛灉姝ｅ湪鍒囨崲搴?璺宠繃
			response.FailWithMessage("姝ｅ湪鍒囨崲鏁版嵁搴撹绛夊緟", c)
			return
		}
		wafLog, _ := wafLogService.GetDetailApi(req)

		if req.OutputFormat == "curl" {
			response.OkWithDetailed(GenerateCurlRequest(wafLog), "鑾峰彇鎴愬姛", c)
		} else {
			response.OkWithDetailed(GenerateRawHTTPRequest(wafLog), "鑾峰彇鎴愬姛", c)
		}

	} else {
		response.FailWithMessage("瑙ｆ瀽澶辫触", c)
	}
}

// GetAttackIPListApi 鑾峰彇椋庨櫓鏁版嵁鍒楄〃
func (w *WafLogAPi) GetAttackIPListApi(c *gin.Context) {
	var req request.WafAttackIpTagSearch
	err := c.ShouldBindJSON(&req)
	if err == nil {
		ipAttackTags, total, err2 := wafLogService.GetAttackIpListApi(req)
		if err2 != nil {
			response.FailWithMessage("璁块棶鍒楄〃澶辫触:"+err2.Error(), c)
		} else {
			response.OkWithDetailed(response.PageResult{
				List:      ipAttackTags,
				Total:     total,
				PageIndex: req.PageIndex,
				PageSize:  req.PageSize,
			}, "鑾峰彇鎴愬姛", c)
		}

	} else {
		response.FailWithMessage("瑙ｆ瀽澶辫触", c)
	}
}

// GetAllIpTagApi 鑾峰彇鎵€鏈塱p tag
func (w *WafLogAPi) GetAllIpTagApi(c *gin.Context) {

	ipAttackTags, err2 := wafLogService.GetAllAttackIPTagListApi()
	if err2 != nil {
		response.FailWithMessage("璁块棶ip tag 澶辫触:"+err2.Error(), c)
	} else {
		response.OkWithDetailed(ipAttackTags, "鑾峰彇鎴愬姛", c)
	}
}

// DeleteTagByNameApi 鍒犻櫎鎸囧畾鏍囩
func (w *WafLogAPi) DeleteTagByNameApi(c *gin.Context) {
	var req request.WafAttackTagDeleteReq
	err := c.ShouldBindJSON(&req)
	if err != nil {
		response.FailWithMessage("鍙傛暟瑙ｆ瀽澶辫触: "+err.Error(), c)
		return
	}

	if global.GDATA_CURRENT_CHANGE {
		//濡傛灉姝ｅ湪鍒囨崲搴?璺宠繃
		response.FailWithMessage("姝ｅ湪鍒囨崲鏁版嵁搴撹绛夊緟", c)
		return
	}

	// 楠岃瘉鏍囩鍚嶇О
	if req.TagName == "" || req.TagName == "姝ｅ父" {
		response.FailWithMessage("鏃犳晥鐨勬爣绛惧悕绉?, c)
		return
	}

	// 鎵ц鍒犻櫎
	err2 := wafLogService.DeleteTagByNameApi(req.TagName, req.DeleteLogs)
	if err2 != nil {
		response.FailWithMessage("鍒犻櫎澶辫触: "+err2.Error(), c)
	} else {
		if req.DeleteLogs {
			response.OkWithMessage("鏍囩鍙婄浉鍏虫棩蹇楀垹闄ゆ垚鍔?, c)
		} else {
			response.OkWithMessage("鏍囩缁熻鏁版嵁鍒犻櫎鎴愬姛", c)
		}
	}
}
func GenerateRawHTTPRequest(weblog innerbean.WebLog) string {

	reqUrl := weblog.URL
	if weblog.SrcURL != nil {
		reqUrl = string(weblog.SrcURL)
	}
	parsedURL, err := url.Parse(reqUrl)
	if err != nil {
		return ""
	}

	// 鏋勫缓璇锋眰琛?
	pathWithQuery := parsedURL.Path
	if parsedURL.RawQuery != "" {
		pathWithQuery += "?" + parsedURL.RawQuery
	}

	// 鏍规嵁鍗忚纭畾 HTTP 鐗堟湰
	httpVersion := "HTTP/1.1"
	if weblog.Scheme != "" {
		httpVersion = weblog.Scheme
	}

	// 澶勭悊鏁忔劅澶翠俊鎭?
	maskedHeaders := maskSensitiveHeader(weblog.HEADER)
	headers := strings.Split(maskedHeaders, "\n")

	// 澶勭悊 Cookie
	maskedCookies := maskSensitiveCookies(weblog.COOKIES)
	if maskedCookies != "" {
		cookieHeader := fmt.Sprintf("Cookie: %s", maskedCookies)
		// 鏇挎崲鎴栨坊鍔?Cookie 澶?
		cookieFound := false
		for i, h := range headers {
			if strings.HasPrefix(strings.TrimSpace(h), "Cookie:") {
				headers[i] = cookieHeader
				cookieFound = true
				break
			}
		}
		if !cookieFound {
			headers = append(headers, cookieHeader)
		}
	}

	// 纭繚 Host 澶村瓨鍦?
	host := parsedURL.Host
	if host != "" {
		hostExists := false
		for _, h := range headers {
			if strings.HasPrefix(strings.TrimSpace(strings.ToLower(h)), "host:") {
				hostExists = true
				break
			}
		}
		if !hostExists {
			headers = append(headers, fmt.Sprintf("Host: %s", host))
		}
	}

	// 鏋勫缓鏈€缁?header
	var cleanHeaders []string
	for _, h := range headers {
		if trimmed := strings.TrimSpace(h); trimmed != "" {
			cleanHeaders = append(cleanHeaders, trimmed)
		}
	}

	// 鏋勫缓瀹屾暣璇锋眰
	requestLines := []string{
		fmt.Sprintf("%s %s %s",
			weblog.METHOD,
			pathWithQuery,
			httpVersion,
		),
	}
	requestLines = append(requestLines, cleanHeaders...)

	// 娣诲姞 body锛堝鏋滄湁锛?
	if weblog.BODY != "" {
		requestLines = append(requestLines, "", weblog.BODY)
	}

	return strings.Join(requestLines, "\n")
}
func GenerateCurlRequest(weblog innerbean.WebLog) string {

	headers := strings.Split(weblog.HEADER, "\n")
	maskedHeaders := maskSensitiveHeader(weblog.HEADER)
	headers = strings.Split(maskedHeaders, "\n")
	headerStrings := ""
	for _, header := range headers {
		headerStrings += fmt.Sprintf("-H '%s' ", strings.TrimSpace(header))
	}

	maskedCookies := maskSensitiveCookies(weblog.COOKIES)

	reqUrl := weblog.URL
	if weblog.SrcURL != nil {
		reqUrl = string(weblog.SrcURL)
	}

	curlCommand := fmt.Sprintf(
		"curl -X %s %s \\\n	--url '%s' \\\n	--cookie '%s' \\\n	--data '%s'",
		weblog.METHOD,
		headerStrings,
		reqUrl,
		maskedCookies,
		weblog.BODY,
	)

	return curlCommand
}
func maskSensitiveHeader(header string) string {
	sensitiveKeys := []string{
		"Authorization", "Token", "Api-Key", "Secret", "Access-Token", "X-Api-Key",
		"X-Access-Token", "X-Secret", "Session-Key", "Set-Cookie",
	}
	maskedHeader := header
	for _, key := range sensitiveKeys {
		regex := regexp.MustCompile(fmt.Sprintf(`(?i)(%s):\s*[^\\n]+`, key))
		maskedHeader = regex.ReplaceAllString(maskedHeader, "$1: [MASKED]")
	}
	return maskedHeader
}

func maskSensitiveCookies(cookies string) string {
	cookieRegex := regexp.MustCompile(`(?i)(sessionid|auth|token|key|secret)=[^;]+`)
	return cookieRegex.ReplaceAllString(cookies, "$1=[MASKED]")
}
