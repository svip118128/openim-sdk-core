package network

import (
	"net/http"
)

// allowCustomHeaders 白名单限定的自定义头部字段，避免外部写入非预期的键。
var allowCustomHeaders = map[string]struct{}{
	http.CanonicalHeaderKey("Authorization"): {},
	http.CanonicalHeaderKey("X-Signature"):   {},
	http.CanonicalHeaderKey("X-Timestamp"):   {},
	http.CanonicalHeaderKey("X-Nonce"):       {},
	http.CanonicalHeaderKey("X-Platform"):    {},
	http.CanonicalHeaderKey("X-OperationId"): {},
	http.CanonicalHeaderKey("X-Device-Id"):   {},
	http.CanonicalHeaderKey("X-Channel"):     {},
	http.CanonicalHeaderKey("X-PackageName"): {},
	http.CanonicalHeaderKey("X-Version"):     {},
	http.CanonicalHeaderKey("X-Brand"):       {},
	http.CanonicalHeaderKey("X-BuildNumber"): {},
}

// applyCustomHeaders 将外部传入的头部值写入请求，仅处理白名单字段且忽略空值。
func applyCustomHeaders(header http.Header, custom map[string]string) {
	if len(custom) == 0 {
		return
	}

	for key, value := range custom {
		if value == "" {
			continue
		}
		canonicalKey := http.CanonicalHeaderKey(key)
		if _, ok := allowCustomHeaders[canonicalKey]; !ok {
			continue
		}
		header.Set(canonicalKey, value)
	}
}
