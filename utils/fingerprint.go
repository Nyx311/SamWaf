package utils

import (
	"crypto/md5"
	"encoding/hex"
	"net/http"
	"sort"
	"strings"
)

type FingerprintDebugInfo struct {
	RawUA   string
	RawAL   string
	RawAE   string
	NormUA  string
	NormAL  string
	NormAE  string
	Data    string
	Hash    string
}

// GenerateFingerprint 生成浏览器指纹
func GenerateFingerprint(r *http.Request) string {
	return GetFingerprintDebugInfo(r).Hash
}

// GetFingerprintDebugInfo 返回指纹计算明细（用于调试）
func GetFingerprintDebugInfo(r *http.Request) FingerprintDebugInfo {
	rawUA := r.UserAgent()
	rawAL := r.Header.Get("Accept-Language")
	rawAE := r.Header.Get("Accept-Encoding")

	normUA := strings.TrimSpace(rawUA)
	normAL := normalizeSimpleHeader(rawAL)
	normAE := normalizeAcceptEncoding(rawAE)

	data := strings.Join([]string{normUA, normAL, normAE}, "|")
	hash := md5.Sum([]byte(data))

	return FingerprintDebugInfo{
		RawUA:  rawUA,
		RawAL:  rawAL,
		RawAE:  rawAE,
		NormUA: normUA,
		NormAL: normAL,
		NormAE: normAE,
		Data:   data,
		Hash:   hex.EncodeToString(hash[:]),
	}
}

func normalizeSimpleHeader(v string) string {
	// 统一大小写与首尾空白，避免代理链路引入的无意义差异
	return strings.ToLower(strings.TrimSpace(v))
}

func normalizeAcceptEncoding(v string) string {
	v = strings.TrimSpace(strings.ToLower(v))
	if v == "" {
		return ""
	}

	items := strings.Split(v, ",")
	normalized := make([]string, 0, len(items))
	seen := make(map[string]struct{}, len(items))

	for _, item := range items {
		token := strings.TrimSpace(item)
		if token == "" {
			continue
		}
		if _, ok := seen[token]; ok {
			continue
		}
		seen[token] = struct{}{}
		normalized = append(normalized, token)
	}

	// 顺序不参与区分，避免 "br,zstd" 与 "zstd,br" 产生误判
	sort.Strings(normalized)
	return strings.Join(normalized, ",")
}
