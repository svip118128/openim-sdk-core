package network

import (
	"testing"
)

func TestParseCustomHeaders_WithNumberPlatform(t *testing.T) {
	headersJSON := `{"X-Platform":2,"X-Device-Id":"7ff13029-094a-4358-be62-29cf9113433b","X-Channel":"test_channel","X-PackageName":"im.flux.one","X-Version":"2.0.3","X-Brand":"google","X-BuildNumber":"2"}`

	values, err := ParseCustomHeaders(headersJSON)
	if err != nil {
		t.Fatalf("ParseCustomHeaders failed: %v", err)
	}

	if values.Platform != 2 {
		t.Errorf("Expected Platform=2, got %d", values.Platform)
	}
	if values.DeviceID != "7ff13029-094a-4358-be62-29cf9113433b" {
		t.Errorf("Expected DeviceID=7ff13029-094a-4358-be62-29cf9113433b, got %s", values.DeviceID)
	}
	if values.Channel != "test_channel" {
		t.Errorf("Expected Channel=test_channel, got %s", values.Channel)
	}
	if values.PackageName != "im.flux.one" {
		t.Errorf("Expected PackageName=im.flux.one, got %s", values.PackageName)
	}
	if values.Version != "2.0.3" {
		t.Errorf("Expected Version=2.0.3, got %s", values.Version)
	}
	if values.Brand != "google" {
		t.Errorf("Expected Brand=google, got %s", values.Brand)
	}
	if values.BuildNumber != "2" {
		t.Errorf("Expected BuildNumber=2, got %s", values.BuildNumber)
	}

	t.Logf("Parsed values: %+v", values)
}

func TestParseCustomHeaders_WithStringPlatform(t *testing.T) {
	headersJSON := `{"X-Platform":"2","X-Device-Id":"device123","X-Channel":"channel","X-PackageName":"com.app","X-Version":"1.0.0","X-Brand":"Apple","X-BuildNumber":"100"}`

	values, err := ParseCustomHeaders(headersJSON)
	if err != nil {
		t.Fatalf("ParseCustomHeaders failed: %v", err)
	}

	if values.Platform != 2 {
		t.Errorf("Expected Platform=2, got %d", values.Platform)
	}

	t.Logf("Parsed values: %+v", values)
}

func TestGenerateSign(t *testing.T) {
	cfg := SignConfig{
		Method:      "POST",
		Path:        "/api/user/login",
		Body:        `{"userID":"test123"}`,
		Secret:      "my-secret-key",
		Platform:    2,
		DeviceID:    "device-123",
		Channel:     "test_channel",
		PackageName: "im.flux.one",
		Version:     "2.0.3",
		Brand:       "google",
		BuildNumber: "2",
		Token:       "token123",
	}

	params := GenerateSign(cfg)

	if params.Nonce == "" {
		t.Error("Nonce should not be empty")
	}
	if len(params.Nonce) != 16 {
		t.Errorf("Expected Nonce length=16, got %d", len(params.Nonce))
	}
	if params.OperationID == "" {
		t.Error("OperationID should not be empty")
	}
	if params.Timestamp == "" {
		t.Error("Timestamp should not be empty")
	}
	if params.Signature == "" {
		t.Error("Signature should not be empty")
	}
	if len(params.Signature) != 64 {
		t.Errorf("Expected Signature length=64 (SHA256 hex), got %d", len(params.Signature))
	}

	t.Logf("SignParams: Nonce=%s, OperationID=%s, Timestamp=%s, Signature=%s",
		params.Nonce, params.OperationID, params.Timestamp, params.Signature)
}

func TestRandomString(t *testing.T) {
	s := RandomString(16)
	if len(s) != 16 {
		t.Errorf("Expected length=16, got %d", len(s))
	}
	t.Logf("RandomString: %s", s)
}

func TestGenerateUuidV4(t *testing.T) {
	uuid := GenerateUuidV4()
	if len(uuid) != 36 {
		t.Errorf("Expected UUID length=36, got %d", len(uuid))
	}
	t.Logf("UUID: %s", uuid)
}

func TestExtractPathFromURL(t *testing.T) {
	tests := []struct {
		url      string
		expected string
	}{
		{"https://api.example.com/api/user/login", "/api/user/login"},
		{"http://localhost:8080/test/path", "/test/path"},
		{"/api/test", "/api/test"},
	}

	for _, tt := range tests {
		path := ExtractPathFromURL(tt.url)
		if path != tt.expected {
			t.Errorf("ExtractPathFromURL(%s) = %s, expected %s", tt.url, path, tt.expected)
		}
	}
}

// go test -v ./pkg/network/... -run "TestParseCustomHeaders|TestGenerateSign|TestRandomString|TestGenerateUuidV4|TestExtractPathFromURL"
