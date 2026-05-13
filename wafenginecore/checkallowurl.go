package wafenginecore

import (
	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/model/detection"
	"SamWaf/model/wafenginmodel"
	"net/http"
	"net/url"
	"strings"
)

/*
*
检测允许的URL
返回是否满足条件
*/
func (waf *WafEngine) CheckAllowURL(r *http.Request, weblogbean *innerbean.WebLog, formValue url.Values, hostTarget *wafenginmodel.HostSafe, globalHostTarget *wafenginmodel.HostSafe) detection.Result {
	result := detection.Result{
		JumpGuardResult: false,
		IsBlock:         false,
		Title:           "",
		Content:         "",
	}
	if hostTarget == nil || weblogbean == nil {
		return result
	}

	// 将请求URL转为小写，用于不区分大小写的比较
	lowerURL := strings.ToLower(weblogbean.URL)

	//url白名单策略（局部）
	if hostTarget.UrlWhiteLists != nil {
		for i := 0; i < len(hostTarget.UrlWhiteLists); i++ {
			// 将规则URL也转为小写
			lowerRuleURL := strings.ToLower(hostTarget.UrlWhiteLists[i].Url)

			if (hostTarget.UrlWhiteLists[i].CompareType == "等于" && lowerRuleURL == lowerURL) ||
				(hostTarget.UrlWhiteLists[i].CompareType == "前缀匹配" && strings.HasPrefix(lowerURL, lowerRuleURL)) ||
				(hostTarget.UrlWhiteLists[i].CompareType == "后缀匹配" && strings.HasSuffix(lowerURL, lowerRuleURL)) ||
				(hostTarget.UrlWhiteLists[i].CompareType == "包含匹配" && strings.Contains(lowerURL, lowerRuleURL)) {
				result.JumpGuardResult = true
				break
			}
		}
	}

	//url白名单策略（全局）
	if globalHostTarget == nil {
		globalHostTarget = waf.HostTarget[global.GWAF_GLOBAL_HOST_NAME]
	}
	if globalHostTarget != nil && globalHostTarget.Host.GUARD_STATUS == 1 && globalHostTarget.UrlWhiteLists != nil {
		for i := 0; i < len(globalHostTarget.UrlWhiteLists); i++ {
			// 将全局规则URL也转为小写
			lowerGlobalRuleURL := strings.ToLower(globalHostTarget.UrlWhiteLists[i].Url)

			if (globalHostTarget.UrlWhiteLists[i].CompareType == "等于" && lowerGlobalRuleURL == lowerURL) ||
				(globalHostTarget.UrlWhiteLists[i].CompareType == "前缀匹配" && strings.HasPrefix(lowerURL, lowerGlobalRuleURL)) ||
				(globalHostTarget.UrlWhiteLists[i].CompareType == "后缀匹配" && strings.HasSuffix(lowerURL, lowerGlobalRuleURL)) ||
				(globalHostTarget.UrlWhiteLists[i].CompareType == "包含匹配" && strings.Contains(lowerURL, lowerGlobalRuleURL)) {
				result.JumpGuardResult = true
				break
			}
		}
	}
	return result
}
