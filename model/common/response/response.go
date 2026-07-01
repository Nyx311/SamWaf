package response

import (
	"SamWaf/common/zlog"
	"SamWaf/global"
	"SamWaf/wafsec"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

type Response struct {
	Code int         `json:"code"`
	Data interface{} `json:"data"`
	Msg  string      `json:"msg"`
}

const (
	ERROR             = -1
	SUCCESS           = 0
	INPUT_SECRET_CODE = -2
	NEED_BIND_2FA     = -3
	FORBIDDEN         = -403
	AUTHFAIL          = -999
)

func Result(code int, data interface{}, msg string, c *gin.Context) {
	if isOpenApi, exists := c.Get("is_openapi"); exists && isOpenApi == true {
		c.JSON(http.StatusOK, Response{code, data, msg})
		return
	}

	result, _ := json.Marshal(data)
	encryptStr, encErr := wafsec.AesEncrypt(result, global.GWAF_COMMUNICATION_KEY)
	if encErr != nil {
		zlog.Warn("Response AES encrypt failed", "path", c.Request.URL.Path, "code", code, "msg", msg, "plain_len", len(result), "err", encErr.Error())
	} else if c != nil && strings.HasPrefix(c.Request.URL.Path, "/api/v1/waflog/attack/") {
		zlog.Debug("Response AES encrypt ok", "path", c.Request.URL.Path, "code", code, "msg", msg, "plain_len", len(result), "cipher_len", len(encryptStr))
	}

	c.JSON(http.StatusOK, Response{code, encryptStr, msg})
}

func Ok(c *gin.Context) {
	Result(SUCCESS, map[string]interface{}{}, "操作成功", c)
}

func OkWithMessage(message string, c *gin.Context) {
	Result(SUCCESS, map[string]interface{}{}, message, c)
}

func OkWithData(data interface{}, c *gin.Context) {
	Result(SUCCESS, data, "查询成功", c)
}

func OkWithDetailed(data interface{}, message string, c *gin.Context) {
	Result(SUCCESS, data, message, c)
}

func Fail(c *gin.Context) {
	Result(ERROR, map[string]interface{}{}, "操作失败", c)
}

func FailWithMessage(message string, c *gin.Context) {
	Result(ERROR, map[string]interface{}{}, message, c)
}

func FailWithDetailed(data interface{}, message string, c *gin.Context) {
	Result(ERROR, data, message, c)
}

func AuthFailWithMessage(message string, c *gin.Context) {
	Result(AUTHFAIL, map[string]interface{}{}, message, c)
}

// ForbiddenWithMessage 已认证但无权限（角色不满足），不触发重新登录
func ForbiddenWithMessage(message string, c *gin.Context) {
	Result(FORBIDDEN, map[string]interface{}{}, message, c)
}
func SecretCodeFailWithMessage(message string, c *gin.Context) {
	Result(INPUT_SECRET_CODE, map[string]interface{}{}, message, c)
}

func NeedBind2FAWithMessage(message string, c *gin.Context) {
	Result(NEED_BIND_2FA, map[string]interface{}{}, message, c)
}
