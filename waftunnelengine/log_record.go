package waftunnelengine

import (
	"SamWaf/common/uuid"
	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/model"
	"fmt"
	"strings"
	"time"
)

// RecordTunnelBlockLog 记录隧道拦截日志到网站防护日志体系
func RecordTunnelBlockLog(protocol string, clientIP string, clientPort string, serverPort string, tunnel model.Tunnel, ruleName string) {
	now := time.Now()
	datetimeNow := now.Format("2006-01-02 15:04:05")

	weblog := &innerbean.WebLog{
		REQ_UUID:             uuid.GenUUID(),
		CREATE_TIME:          datetimeNow,
		UNIX_ADD_TIME:        now.UnixNano() / 1e6,
		Day:                  now.Day(),
		HOST:                 tunnel.Name,
		HOST_CODE:            tunnel.Code,
		URL:                  fmt.Sprintf("%s://0.0.0.0:%s", strings.ToLower(protocol), serverPort),
		METHOD:               strings.ToUpper(protocol),
		SRC_IP:               clientIP,
		SRC_PORT:             clientPort,
		ACTION:               "阻止",
		RULE:                 ruleName,
		STATUS:               "阻止访问",
		RISK_LEVEL:           1,
		GUEST_IDENTIFICATION: "可疑用户",
		TASK_FLAG:            1,
		USER_CODE:            global.GWAF_USER_CODE,
		TenantId:             global.GWAF_TENANT_ID,
	}

	global.GQEQUE_LOG_DB.Enqueue(weblog)
}