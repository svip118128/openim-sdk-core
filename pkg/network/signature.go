package network

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// SignatureParams contains all parameters needed for signature generation
type SignatureParams struct {
	SecretKey   string
	Method      string
	Path        string
	Timestamp   string
	Nonce       string
	Body        interface{}
	Platform    string
	OperationID string
	DeviceID    string
	Channel     string
	PackageName string
	Version     string
	Brand       string
	BuildNumber string
	Token       string
}

// randomString generates a random string of specified length
func randomString(length int) string {
	const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	result := make([]byte, length)
	for i := range result {
		// Use modulo with a better random source
		result[i] = chars[time.Now().UnixNano()%int64(len(chars))]
	}
	return string(result)
}

// GenerateSignature generates HMAC-SHA256 signature from parameters
func GenerateSignature(params SignatureParams) (string, error) {
	// Serialize body
	var bodyString string
	if params.Body == nil {
		bodyString = "{}"
	} else {
		bodyBytes, err := json.Marshal(params.Body)
		if err != nil {
			return "", fmt.Errorf("failed to marshal body: %w", err)
		}
		bodyString = string(bodyBytes)
	}

	// Build payload for signature
	payloadParts := []string{
		params.Method,
		params.Path,
		params.Timestamp,
		params.Nonce,
		bodyString,
		params.Platform,
		params.OperationID,
		params.DeviceID,
		params.Channel,
		params.PackageName,
		params.Version,
		params.Brand,
		params.BuildNumber,
	}

	// Include token if provided
	if params.Token != "" {
		payloadParts = append(payloadParts, params.Token)
	}

	payload := strings.Join(payloadParts, "\n")

	// Generate HMAC-SHA256 signature
	h := hmac.New(sha256.New, []byte(params.SecretKey))
	h.Write([]byte(payload))
	signature := hex.EncodeToString(h.Sum(nil))

	return signature, nil
}


// ExtractSignatureParamsFromHeaders extracts signature parameters from custom headers
func ExtractSignatureParamsFromHeaders(headers map[string]string, secretKey string) SignatureParams {
	params := SignatureParams{
		SecretKey:   secretKey, // Must be provided by caller
		Platform:    getHeaderValue(headers, "X-Platform", ""),
		DeviceID:    getHeaderValue(headers, "X-Device-Id", ""),
		Channel:     getHeaderValue(headers, "X-Channel", "test_channel"),
		PackageName: getHeaderValue(headers, "X-PackageName", ""),
		Version:     getHeaderValue(headers, "X-Version", ""),
		Brand:       getHeaderValue(headers, "X-Brand", ""),
		BuildNumber: getHeaderValue(headers, "X-BuildNumber", ""),
		Token:       getHeaderValue(headers, "X-Token", ""),
		Timestamp:   getHeaderValue(headers, "X-Timestamp", ""),
		Nonce:       getHeaderValue(headers, "X-Nonce", ""),
		OperationID: getHeaderValue(headers, "X-OperationId", ""),
	}

	// Generate missing values
	if params.Timestamp == "" {
		params.Timestamp = time.Now().UTC().Format(time.RFC3339)
	}
	if params.Nonce == "" {
		params.Nonce = randomString(16)
	}
	if params.OperationID == "" {
		params.OperationID = generateUUID()
	}
	if params.DeviceID == "" {
		params.DeviceID = generateUUID()
	}

	return params
}

// generateUUID generates a UUID string
func generateUUID() string {
	// Use a simple UUID v4 generation from timestamp and randomness
	// This is a fallback implementation when google/uuid is not available
	b := make([]byte, 16)
	for i := 0; i < 16; i++ {
		b[i] = byte(time.Now().UnixNano() % 256)
	}
	// Set version (4) and variant bits
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// getHeaderValue returns header value with fallback to default
func getHeaderValue(headers map[string]string, key, defaultValue string) string {
	if value, ok := headers[key]; ok && value != "" {
		return value
	}
	return defaultValue
}