package network

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type SignParams struct {
	Timestamp   string
	Nonce       string
	OperationID string
	Signature   string
}

func RandomString(length int) string {
	const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	result := make([]byte, length)
	randomBytes := make([]byte, length)
	_, err := rand.Read(randomBytes)
	if err != nil {
		for i := range result {
			result[i] = chars[time.Now().UnixNano()%int64(len(chars))]
		}
		return string(result)
	}
	for i, b := range randomBytes {
		result[i] = chars[int(b)%len(chars)]
	}
	return string(result)
}

func GenerateUuidV4() string {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

type SignConfig struct {
	Method      string
	Path        string
	Body        string
	Secret      string
	Platform    int32
	DeviceID    string
	Channel     string
	PackageName string
	Version     string
	Brand       string
	BuildNumber string
	Token       string
}

func getPayloadOrder(channel string) []string {
	switch channel {
	case "FX_iOS_2512", "JC_AP_iOS_2512":
		return []string{"method", "path", "timestamp", "nonce", "body", "platform", "operationId", "deviceId", "channel", "packageName", "version", "brand", "buildNumber"}
	case "FX_APK_2512", "JC_GP_APK_2512":
		return []string{"path", "method", "body", "nonce", "timestamp", "platform", "deviceId", "operationId", "channel", "packageName", "version", "buildNumber", "brand"}
	case "FX_PC_2512", "JC_PC_2512":
		return []string{"method", "body", "path", "timestamp", "nonce", "platform", "operationId", "channel", "deviceId", "packageName", "version", "brand", "buildNumber"}
	case "FX_MAC_2512", "JC_MAC_2512":
		return []string{"path", "method", "timestamp", "body", "nonce", "platform", "operationId", "deviceId", "packageName", "channel", "version", "buildNumber", "brand"}
	case "FX_WEB_2512", "JC_WEB_2512":
		return []string{"method", "path", "nonce", "timestamp", "body", "platform", "operationId", "deviceId", "channel", "version", "packageName", "brand", "buildNumber"}
	case "FX_H5_2512", "JC_H5_2512":
		return []string{"body", "method", "path", "timestamp", "nonce", "platform", "operationId", "deviceId", "channel", "packageName", "brand", "version", "buildNumber"}
	default:
		return []string{"method", "path", "body", "timestamp", "nonce", "platform", "operationId", "deviceId", "channel", "packageName", "version", "brand", "buildNumber"}
	}
}

func GenerateSign(cfg SignConfig) SignParams {
	nonce := RandomString(16)
	operationID := GenerateUuidV4()
	timestamp := time.Now().UTC().Format(time.RFC3339Nano)

	order := getPayloadOrder(cfg.Channel)
	payloadParts := make([]string, len(order))

	valueMap := map[string]string{
		"method":      cfg.Method,
		"path":        cfg.Path,
		"body":        cfg.Body,
		"timestamp":   timestamp,
		"nonce":       nonce,
		"platform":    strconv.Itoa(int(cfg.Platform)),
		"operationId": operationID,
		"deviceId":    cfg.DeviceID,
		"channel":     cfg.Channel,
		"packageName": cfg.PackageName,
		"version":     cfg.Version,
		"brand":       cfg.Brand,
		"buildNumber": cfg.BuildNumber,
	}

	for i, key := range order {
		payloadParts[i] = valueMap[key]
	}

	payload := strings.Join(payloadParts, "\n")

	h := hmac.New(sha256.New, []byte(cfg.Secret))
	h.Write([]byte(payload))
	signature := hex.EncodeToString(h.Sum(nil))

	return SignParams{
		Timestamp:   timestamp,
		Nonce:       nonce,
		OperationID: operationID,
		Signature:   signature,
	}
}

func ExtractPathFromURL(fullURL string) string {
	parsed, err := url.Parse(fullURL)
	if err != nil {
		return fullURL
	}
	return parsed.Path
}

type CustomHeaderValues struct {
	Platform    int32
	DeviceID    string
	Channel     string
	PackageName string
	Version     string
	Brand       string
	BuildNumber string
}

func ParseCustomHeaders(headersJSON string) (*CustomHeaderValues, error) {
	if headersJSON == "" {
		return &CustomHeaderValues{}, nil
	}

	var headers map[string]interface{}
	if err := json.Unmarshal([]byte(headersJSON), &headers); err != nil {
		return nil, err
	}

	values := &CustomHeaderValues{}

	if v, ok := headers["X-Platform"]; ok {
		switch val := v.(type) {
		case float64:
			values.Platform = int32(val)
		case string:
			if p, err := strconv.Atoi(val); err == nil {
				values.Platform = int32(p)
			}
		}
	}
	values.DeviceID = getStringValue(headers, "X-Device-Id")
	values.Channel = getStringValue(headers, "X-Channel")
	values.PackageName = getStringValue(headers, "X-PackageName")
	values.Version = getStringValue(headers, "X-Version")
	values.Brand = getStringValue(headers, "X-Brand")
	values.BuildNumber = getStringValue(headers, "X-BuildNumber")

	return values, nil
}

func getStringValue(m map[string]interface{}, key string) string {
	if v, ok := m[key]; ok {
		switch val := v.(type) {
		case string:
			return val
		case float64:
			return strconv.Itoa(int(val))
		}
	}
	return ""
}
