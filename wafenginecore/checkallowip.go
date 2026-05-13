package wafenginecore

import (
	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/model"
	"SamWaf/model/detection"
	"SamWaf/model/wafenginmodel"
	"SamWaf/utils"
	"net/http"
	"net/url"
)

/*
*
检测白名单 ip
*/
func (waf *WafEngine) CheckAllowIP(r *http.Request, weblogbean *innerbean.WebLog, formValue url.Values, hostTarget *wafenginmodel.HostSafe, globalHostTarget *wafenginmodel.HostSafe) detection.Result {
	result := detection.Result{
		JumpGuardResult: false,
		IsBlock:         false,
		Title:           "",
		Content:         "",
	}
	if hostTarget == nil || weblogbean == nil {
		return result
	}
	// 根据当前 host 的 IP 模式选择使用的 IP
	clientIp := model.GetClientIPByMode(hostTarget.Host.IPMode, weblogbean.NetSrcIp, weblogbean.SRC_IP)

	//ip白名单策略（局部）
	if hostTarget.IPWhiteLists != nil {
		for i := 0; i < len(hostTarget.IPWhiteLists); i++ {
			if utils.CheckIPInCIDR(clientIp, hostTarget.IPWhiteLists[i].Ip) {
				result.JumpGuardResult = true
				break
			}
		}
	}
	//ip白名单策略（全局）
	if globalHostTarget == nil {
		globalHostTarget = waf.HostTarget[global.GWAF_GLOBAL_HOST_NAME]
	}
	if globalHostTarget != nil && globalHostTarget.Host.GUARD_STATUS == 1 && globalHostTarget.IPWhiteLists != nil {
		for i := 0; i < len(globalHostTarget.IPWhiteLists); i++ {
			if utils.CheckIPInCIDR(clientIp, globalHostTarget.IPWhiteLists[i].Ip) {
				result.JumpGuardResult = true
				break
			}
		}
	}
	return result
}
