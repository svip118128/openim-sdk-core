package network

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
	"testing"
)

func TestGetPayloadOrder(t *testing.T) {
	tests := []struct {
		channel string
		want    []string
	}{
		{
			channel: "FX_iOS_2512",
			want:    []string{"method", "path", "timestamp", "nonce", "body", "platform", "operationId", "deviceId", "channel", "packageName", "version", "brand", "buildNumber"},
		},
		{
			channel: "JC_AP_iOS_2512",
			want:    []string{"method", "path", "timestamp", "nonce", "body", "platform", "operationId", "deviceId", "channel", "packageName", "version", "brand", "buildNumber"},
		},
		{
			channel: "FX_APK_2512",
			want:    []string{"path", "method", "body", "nonce", "timestamp", "platform", "deviceId", "operationId", "channel", "packageName", "version", "buildNumber", "brand"},
		},
		{
			channel: "JC_GP_APK_2512",
			want:    []string{"path", "method", "body", "nonce", "timestamp", "platform", "deviceId", "operationId", "channel", "packageName", "version", "buildNumber", "brand"},
		},
		{
			channel: "FX_PC_2512",
			want:    []string{"method", "body", "path", "timestamp", "nonce", "platform", "operationId", "channel", "deviceId", "packageName", "version", "brand", "buildNumber"},
		},
		{
			channel: "JC_PC_2512",
			want:    []string{"method", "body", "path", "timestamp", "nonce", "platform", "operationId", "channel", "deviceId", "packageName", "version", "brand", "buildNumber"},
		},
		{
			channel: "FX_MAC_2512",
			want:    []string{"path", "method", "timestamp", "body", "nonce", "platform", "operationId", "deviceId", "packageName", "channel", "version", "buildNumber", "brand"},
		},
		{
			channel: "JC_MAC_2512",
			want:    []string{"path", "method", "timestamp", "body", "nonce", "platform", "operationId", "deviceId", "packageName", "channel", "version", "buildNumber", "brand"},
		},
		{
			channel: "FX_WEB_2512",
			want:    []string{"method", "path", "nonce", "timestamp", "body", "platform", "operationId", "deviceId", "channel", "version", "packageName", "brand", "buildNumber"},
		},
		{
			channel: "JC_WEB_2512",
			want:    []string{"method", "path", "nonce", "timestamp", "body", "platform", "operationId", "deviceId", "channel", "version", "packageName", "brand", "buildNumber"},
		},
		{
			channel: "FX_H5_2512",
			want:    []string{"body", "method", "path", "timestamp", "nonce", "platform", "operationId", "deviceId", "channel", "packageName", "brand", "version", "buildNumber"},
		},
		{
			channel: "JC_H5_2512",
			want:    []string{"body", "method", "path", "timestamp", "nonce", "platform", "operationId", "deviceId", "channel", "packageName", "brand", "version", "buildNumber"},
		},
		{
			channel: "UNKNOWN_CHANNEL",
			want:    []string{"method", "path", "body", "timestamp", "nonce", "platform", "operationId", "deviceId", "channel", "packageName", "version", "brand", "buildNumber"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.channel, func(t *testing.T) {
			got := getPayloadOrder(tt.channel)
			if len(got) != len(tt.want) {
				t.Errorf("getPayloadOrder() length = %v, want %v", len(got), len(tt.want))
				return
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("getPayloadOrder()[%d] = %v, want %v", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestGenerateSign_DifferentChannels_DifferentPayloadOrder(t *testing.T) {
	baseCfg := SignConfig{
		Method:      "POST",
		Path:        "/api/test",
		Body:        `{"test":"data"}`,
		Secret:      "test-secret-key",
		Platform:    1,
		DeviceID:    "device-123",
		PackageName: "com.test.app",
		Version:     "1.0.0",
		Brand:       "test-brand",
		BuildNumber: "100",
	}

	channels := []string{
		"FX_iOS_2512",
		"FX_APK_2512",
		"FX_PC_2512",
		"FX_MAC_2512",
		"FX_WEB_2512",
		"FX_H5_2512",
	}

	signatures := make(map[string]string)
	payloads := make(map[string]string)

	for _, channel := range channels {
		cfg := baseCfg
		cfg.Channel = channel

		result := GenerateSign(cfg)
		signatures[channel] = result.Signature
		payloads[channel] = buildPayloadForChannel(cfg, channel, result.Timestamp, result.Nonce, result.OperationID)
	}

	for i, ch1 := range channels {
		for j, ch2 := range channels {
			if i >= j {
				continue
			}
			if signatures[ch1] == signatures[ch2] {
				t.Errorf("Channels %s and %s produced the same signature, but should have different payload orders", ch1, ch2)
			}
		}
	}
}

func buildPayloadForChannel(cfg SignConfig, channel string, timestamp string, nonce string, operationID string) string {
	order := getPayloadOrder(channel)
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

	return strings.Join(payloadParts, "\n")
}

func TestGenerateSign_SameChannel_SameOrder(t *testing.T) {
	cfg1 := SignConfig{
		Method:      "POST",
		Path:        "/api/test",
		Body:        `{"test":"data"}`,
		Secret:      "test-secret-key",
		Platform:    1,
		DeviceID:    "device-123",
		Channel:     "FX_iOS_2512",
		PackageName: "com.test.app",
		Version:     "1.0.0",
		Brand:       "test-brand",
		BuildNumber: "100",
	}

	cfg2 := cfg1

	result1 := GenerateSign(cfg1)
	result2 := GenerateSign(cfg2)

	if result1.Signature == result2.Signature {
		t.Error("Same config should produce different signatures due to different nonce/timestamp/operationID")
	}

	if result1.Nonce == result2.Nonce {
		t.Error("Nonce should be different for each call")
	}

	if result1.OperationID == result2.OperationID {
		t.Error("OperationID should be different for each call")
	}
}

func TestGenerateSign_VerifySignature(t *testing.T) {
	cfg := SignConfig{
		Method:      "POST",
		Path:        "/api/test",
		Body:        `{"test":"data"}`,
		Secret:      "test-secret-key",
		Platform:    1,
		DeviceID:    "device-123",
		Channel:     "FX_iOS_2512",
		PackageName: "com.test.app",
		Version:     "1.0.0",
		Brand:       "test-brand",
		BuildNumber: "100",
	}

	result := GenerateSign(cfg)

	order := getPayloadOrder(cfg.Channel)
	payloadParts := make([]string, len(order))

	valueMap := map[string]string{
		"method":      cfg.Method,
		"path":        cfg.Path,
		"body":        cfg.Body,
		"timestamp":   result.Timestamp,
		"nonce":       result.Nonce,
		"platform":    "1",
		"operationId": result.OperationID,
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
	expectedSignature := hex.EncodeToString(h.Sum(nil))

	if result.Signature != expectedSignature {
		t.Errorf("Signature mismatch. Got %s, expected %s", result.Signature, expectedSignature)
	}
}

func TestGenerateSign_AllChannels(t *testing.T) {
	channels := []string{
		"FX_iOS_2512",
		"JC_AP_iOS_2512",
		"FX_APK_2512",
		"JC_GP_APK_2512",
		"FX_PC_2512",
		"JC_PC_2512",
		"FX_MAC_2512",
		"JC_MAC_2512",
		"FX_WEB_2512",
		"JC_WEB_2512",
		"FX_H5_2512",
		"JC_H5_2512",
	}

	cfg := SignConfig{
		Method:      "POST",
		Path:        "/api/test",
		Body:        `{"test":"data"}`,
		Secret:      "test-secret-key",
		Platform:    1,
		DeviceID:    "device-123",
		PackageName: "com.test.app",
		Version:     "1.0.0",
		Brand:       "test-brand",
		BuildNumber: "100",
	}

	for _, channel := range channels {
		t.Run(channel, func(t *testing.T) {
			cfg.Channel = channel
			result := GenerateSign(cfg)

			if result.Signature == "" {
				t.Error("Signature should not be empty")
			}

			if result.Timestamp == "" {
				t.Error("Timestamp should not be empty")
			}

			if result.Nonce == "" {
				t.Error("Nonce should not be empty")
			}

			if result.OperationID == "" {
				t.Error("OperationID should not be empty")
			}

			if len(result.Nonce) != 16 {
				t.Errorf("Nonce length should be 16, got %d", len(result.Nonce))
			}
		})
	}
}
