package network

import (
	"encoding/json"
	"net/http"
)

var allowCustomHeaders = map[string]struct{}{
	http.CanonicalHeaderKey("Authorization"): {},
	http.CanonicalHeaderKey("X-Signature"):   {},
	http.CanonicalHeaderKey("X-Timestamp"):   {},
	http.CanonicalHeaderKey("X-Nonce"):       {},
	http.CanonicalHeaderKey("X-Platform"):    {},
	http.CanonicalHeaderKey("X-Device-Id"):   {},
	http.CanonicalHeaderKey("X-Channel"):     {},
	http.CanonicalHeaderKey("X-PackageName"): {},
	http.CanonicalHeaderKey("X-Version"):     {},
	http.CanonicalHeaderKey("X-Brand"):       {},
	http.CanonicalHeaderKey("X-BuildNumber"): {},
	http.CanonicalHeaderKey("X-Token"):       {},
	http.CanonicalHeaderKey("X-OperationId"): {},
	http.CanonicalHeaderKey("X-Secret"):      {},
}

func ApplyCustomHeaders(header http.Header, headersJSON string) error {
	if headersJSON == "" {
		return nil
	}
	var custom map[string]string
	if err := json.Unmarshal([]byte(headersJSON), &custom); err != nil {
		return err
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
	return nil
}
