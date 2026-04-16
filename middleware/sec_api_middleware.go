package middleware

import (
	"SamWaf/common/zlog"
	"SamWaf/global"
	"SamWaf/wafsec"
	"bytes"
	"github.com/gin-gonic/gin"
	"io"
	"net/http"
	"strings"
)

// SecApi 鉴权中间件
func SecApi() gin.HandlerFunc {
	return func(c *gin.Context) {
		bodyBytes, err := io.ReadAll(c.Request.Body)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to read request body"})
			c.Abort()
			return
		}
		if strings.HasPrefix(c.Request.URL.Path, "/api/v1/waflog/attack/") {
			zlog.Debug("SecApi request body", "path", c.Request.URL.Path, "content_type", c.Request.Header.Get("Content-Type"), "accept", c.Request.Header.Get("accept"), "body_len", len(bodyBytes))
		}
		c.Request.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

		if c.Request.Header.Get("Content-Type") == "application/x-www-form-urlencoded" {
			decryptBytes, err := wafsec.AesDecrypt(string(bodyBytes), global.GWAF_COMMUNICATION_KEY)
			if err == nil {
				c.Request.Body = io.NopCloser(bytes.NewBuffer(decryptBytes))
				if strings.HasPrefix(c.Request.URL.Path, "/api/v1/waflog/attack/") {
					zlog.Debug("SecApi decrypt ok", "path", c.Request.URL.Path, "mode", "form-urlencoded", "decrypt_len", len(decryptBytes))
				}
			} else if strings.HasPrefix(c.Request.URL.Path, "/api/v1/waflog/attack/") {
				zlog.Warn("SecApi decrypt failed", "path", c.Request.URL.Path, "mode", "form-urlencoded", "err", err.Error())
			}

		} else if strings.Contains(c.Request.Header.Get("accept"), "text/event-stream") {
			decryptBytes, err := wafsec.AesDecrypt(string(bodyBytes), global.GWAF_COMMUNICATION_KEY)
			if err == nil {
				c.Request.Body = io.NopCloser(bytes.NewBuffer(decryptBytes))
				if strings.HasPrefix(c.Request.URL.Path, "/api/v1/waflog/attack/") {
					zlog.Debug("SecApi decrypt ok", "path", c.Request.URL.Path, "mode", "event-stream", "decrypt_len", len(decryptBytes))
				}
			} else if strings.HasPrefix(c.Request.URL.Path, "/api/v1/waflog/attack/") {
				zlog.Warn("SecApi decrypt failed", "path", c.Request.URL.Path, "mode", "event-stream", "err", err.Error())
			}
		} else if c.Request.Header.Get("X-Login-Type") == "mobile" && c.Request.Header.Get("Content-Type") == "application/json" {
			decryptBytes, err := wafsec.AesDecrypt(string(bodyBytes), global.GWAF_COMMUNICATION_KEY)
			if err == nil {
				c.Request.Body = io.NopCloser(bytes.NewBuffer(decryptBytes))
				if strings.HasPrefix(c.Request.URL.Path, "/api/v1/waflog/attack/") {
					zlog.Debug("SecApi decrypt ok", "path", c.Request.URL.Path, "mode", "mobile-json", "decrypt_len", len(decryptBytes))
				}
			} else {
				zlog.Debug("Decrypt error", err.Error())
				if strings.HasPrefix(c.Request.URL.Path, "/api/v1/waflog/attack/") {
					zlog.Warn("SecApi decrypt failed", "path", c.Request.URL.Path, "mode", "mobile-json", "err", err.Error())
				}
			}

		}
		c.Next()
	}
}
