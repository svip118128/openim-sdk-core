package secret_manager

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// SecretConfig holds the configuration for the secret manager
type SecretConfig struct {
	ConfigCenterURL string `json:"configCenterURL"`
	Actor           string `json:"actor"`
	CSRFToken       string `json:"csrfToken"`
	Namespace       string `json:"namespace"`
	SecretName      string `json:"secretName"`
	RefreshInterval int    `json:"refreshInterval"` // legacy: used if expireAt not provided

	// Device info for signature
	Platform    int    `json:"platform"`
	DeviceID    string `json:"deviceID"`
	Channel     string `json:"channel"`
	PackageName string `json:"packageName"`
	Version     string `json:"version"`
	Brand       string `json:"brand"`
	BuildNumber string `json:"buildNumber"`
}

// SecretResponse represents the structure of the secret response from Config Center
type SecretResponse struct {
	Plaintext   string                 `json:"plaintext"`
	ExpireAt    int64                  `json:"expireAt"`    // Unix timestamp
	ExpireAtMap map[string]interface{} `json:"expireAtMap"` // Alternative location for expiry
	ErrCode     int                    `json:"errCode"`
	ErrMsg      string                 `json:"errMsg"`
}

// SecretManager manages fetching and refreshing secrets from Config Center
type SecretManager struct {
	config        *SecretConfig
	currentSecret string
	currentToken  string
	nextRefresh   time.Time
	mu            sync.RWMutex
	stopChan      chan struct{}
	httpClient    *http.Client

	// Callback when secret changes
	OnSecretChanged func(secret string)
}

// NewSecretManager creates a new SecretManager instance
func NewSecretManager(config *SecretConfig) *SecretManager {
	return &SecretManager{
		config:     config,
		stopChan:   make(chan struct{}),
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
}

// Start begins the secret manager asynchronously.
// It will try to fetch the secret immediately, but won't block if it fails initially.
// It will keep retrying in the background.
func (m *SecretManager) Start() error {
	// Start the background loop immediately
	go m.refreshLoop()
	return nil
}

// Stop stops the auto-refresh loop
func (m *SecretManager) Stop() {
	close(m.stopChan)
}

// GetSecret returns the current secret
func (m *SecretManager) GetSecret() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.currentSecret
}

// RefreshNow fetches a new secret from Config Center
func (m *SecretManager) RefreshNow() (time.Time, error) {
	// Fetch token first
	token, err := m.fetchToken()
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to fetch token: %w", err)
	}

	m.mu.Lock()
	m.currentToken = token
	m.mu.Unlock()

	// Fetch secret using the token
	secret, expireAt, err := m.fetchSecret()
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to fetch secret: %w", err)
	}

	m.mu.Lock()
	oldSecret := m.currentSecret
	m.currentSecret = secret
	m.mu.Unlock()

	// Notify if secret changed
	if oldSecret != secret && m.OnSecretChanged != nil {
		m.OnSecretChanged(secret)
	}

	// Calculate next refresh time
	// Refresh a bit before expiration (e.g., at 90% of lifetime or 5 mins before)
	now := time.Now()
	if !expireAt.IsZero() && expireAt.After(now) {
		lifetime := expireAt.Sub(now)
		// Refresh at 80% of lifetime or 5 mins before, whichever is later/safer
		refreshIn := time.Duration(float64(lifetime) * 0.8)
		return now.Add(refreshIn), nil
	}

	// Fallback to fixed interval if no valid expiry
	interval := m.config.RefreshInterval
	if interval <= 0 {
		interval = 300 // Default 5 mins
	}
	return now.Add(time.Duration(interval) * time.Second), nil
}

func (m *SecretManager) refreshLoop() {
	// Initial fetch
	nextRefresh, err := m.RefreshNow()
	if err != nil {
		fmt.Printf("[SecretManager] Initial fetch failed: %v. Retrying in 10s...\n", err)
		nextRefresh = time.Now().Add(10 * time.Second)
	}

	timer := time.NewTimer(time.Until(nextRefresh))
	defer timer.Stop()

	for {
		select {
		case <-timer.C:
			next, err := m.RefreshNow()
			if err != nil {
				fmt.Printf("[SecretManager] Refresh failed: %v. Retrying in 30s...\n", err)
				// Retry sooner on failure
				timer.Reset(30 * time.Second)
			} else {
				// Schedule next normal refresh
				timer.Reset(time.Until(next))
				fmt.Printf("[SecretManager] Secret refreshed. Next refresh at: %v\n", next)
			}
		case <-m.stopChan:
			return
		}
	}
}

// fetchToken fetches a new token from Config Center using Ed25519 signature
func (m *SecretManager) fetchToken() (string, error) {
	// Generate Ed25519 keypair
	publicKey, privateKey, err := GenerateEd25519Keypair()
	if err != nil {
		return "", fmt.Errorf("failed to generate keypair: %w", err)
	}

	// Build request
	url := strings.TrimSuffix(m.config.ConfigCenterURL, "/") + "/v1/auth/get_token"
	method := "POST"
	path := "/v1/auth/get_token"

	publicKeyHex := hex.EncodeToString(publicKey)
	body := map[string]interface{}{
		"publicKey": publicKeyHex,
	}
	bodyBytes, _ := json.Marshal(body)

	// Generate signature
	timestamp := time.Now().UTC().Format(time.RFC3339Nano)
	nonce := randomString(32)
	operationID := uuid.New().String()

	payload := BuildTokenPayload(method, path, timestamp, nonce, bodyBytes, DeviceInfo{
		Platform:    m.config.Platform,
		DeviceID:    m.config.DeviceID,
		Channel:     m.config.Channel,
		PackageName: m.config.PackageName,
		Version:     m.config.Version,
		Brand:       m.config.Brand,
		BuildNumber: m.config.BuildNumber,
	})

	signature, err := SignPayload(privateKey, payload)
	if err != nil {
		return "", fmt.Errorf("failed to sign payload: %w", err)
	}

	// Create HTTP request
	req, err := http.NewRequest(method, url, bytes.NewReader(bodyBytes))
	if err != nil {
		return "", err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Actor", m.config.Actor)
	req.Header.Set("x-csrf-token", m.config.CSRFToken)
	req.Header.Set("X-Signature", signature)
	req.Header.Set("X-Timestamp", timestamp)
	req.Header.Set("X-Nonce", nonce)
	req.Header.Set("X-Platform", fmt.Sprintf("%d", m.config.Platform))
	req.Header.Set("X-OperationId", operationID)
	req.Header.Set("X-Device-Id", m.config.DeviceID)
	req.Header.Set("X-Channel", m.config.Channel)
	req.Header.Set("X-PackageName", m.config.PackageName)
	req.Header.Set("X-Version", m.config.Version)
	req.Header.Set("X-Brand", m.config.Brand)
	req.Header.Set("X-BuildNumber", m.config.BuildNumber)

	resp, err := m.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	var result struct {
		Token   string `json:"token"`
		ErrCode int    `json:"errCode"`
		ErrMsg  string `json:"errMsg"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return "", fmt.Errorf("failed to parse response: %w", err)
	}

	if result.ErrCode != 0 {
		return "", fmt.Errorf("config center error: %d - %s", result.ErrCode, result.ErrMsg)
	}

	return result.Token, nil
}

// fetchSecret fetches the secret from Config Center using the current token
func (m *SecretManager) fetchSecret() (string, time.Time, error) {
	m.mu.RLock()
	token := m.currentToken
	m.mu.RUnlock()

	if token == "" {
		return "", time.Time{}, fmt.Errorf("no token available")
	}

	// Generate Ed25519 keypair for this request
	publicKey, privateKey, err := GenerateEd25519Keypair()
	if err != nil {
		return "", time.Time{}, fmt.Errorf("failed to generate keypair: %w", err)
	}

	// Build request
	path := fmt.Sprintf("/v1/namespaces/%s/secrets/%s:get", m.config.Namespace, m.config.SecretName)
	url := strings.TrimSuffix(m.config.ConfigCenterURL, "/") + path
	method := "POST"

	publicKeyHex := hex.EncodeToString(publicKey)
	body := map[string]interface{}{
		"publicKey": publicKeyHex,
	}
	bodyBytes, _ := json.Marshal(body)

	// Generate signature
	timestamp := time.Now().UTC().Format(time.RFC3339Nano)
	nonce := randomString(32)
	operationID := uuid.New().String()

	payload := BuildTokenPayload(method, path, timestamp, nonce, bodyBytes, DeviceInfo{
		Platform:    m.config.Platform,
		DeviceID:    m.config.DeviceID,
		Channel:     m.config.Channel,
		PackageName: m.config.PackageName,
		Version:     m.config.Version,
		Brand:       m.config.Brand,
		BuildNumber: m.config.BuildNumber,
	})

	signature, err := SignPayload(privateKey, payload)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("failed to sign payload: %w", err)
	}

	// Create HTTP request
	req, err := http.NewRequest(method, url, bytes.NewReader(bodyBytes))
	if err != nil {
		return "", time.Time{}, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Actor", m.config.Actor)
	req.Header.Set("x-csrf-token", m.config.CSRFToken)
	req.Header.Set("X-Signature", signature)
	req.Header.Set("X-Timestamp", timestamp)
	req.Header.Set("X-Nonce", nonce)
	req.Header.Set("X-Platform", fmt.Sprintf("%d", m.config.Platform))
	req.Header.Set("X-OperationId", operationID)
	req.Header.Set("X-Device-Id", m.config.DeviceID)
	req.Header.Set("X-Channel", m.config.Channel)
	req.Header.Set("X-PackageName", m.config.PackageName)
	req.Header.Set("X-Version", m.config.Version)
	req.Header.Set("X-Brand", m.config.Brand)
	req.Header.Set("X-BuildNumber", m.config.BuildNumber)

	resp, err := m.httpClient.Do(req)
	if err != nil {
		return "", time.Time{}, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", time.Time{}, err
	}

	var result SecretResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return "", time.Time{}, fmt.Errorf("failed to parse response: %w", err)
	}

	if result.ErrCode != 0 {
		return "", time.Time{}, fmt.Errorf("config center error: %d - %s", result.ErrCode, result.ErrMsg)
	}

	// Try to get expiry time
	var expireAtTime time.Time
	if result.ExpireAt > 0 {
		expireAtTime = time.Unix(result.ExpireAt, 0)
	}

	return result.Plaintext, expireAtTime, nil
}

// DeviceInfo holds device information for signature generation
type DeviceInfo struct {
	Platform    int
	DeviceID    string
	Channel     string
	PackageName string
	Version     string
	Brand       string
	BuildNumber string
}

// GenerateEd25519Keypair generates a new Ed25519 keypair
func GenerateEd25519Keypair() (publicKey, privateKey []byte, err error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return pub, priv, nil
}

// SignPayload signs a payload using Ed25519 private key
func SignPayload(privateKey []byte, payload string) (string, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return "", fmt.Errorf("invalid private key size")
	}

	signature := ed25519.Sign(privateKey, []byte(payload))
	return hex.EncodeToString(signature), nil
}

// BuildTokenPayload builds the payload string for signing
func BuildTokenPayload(method, path, timestamp, nonce string, body []byte, info DeviceInfo) string {
	parts := []string{
		strings.ToUpper(method),
		path,
		timestamp,
		nonce,
		string(body),
		fmt.Sprintf("%d", info.Platform),
		uuid.New().String(), // operationId - will be regenerated, but structure matters
		info.DeviceID,
		info.Channel,
		info.PackageName,
		info.Version,
		info.Brand,
		info.BuildNumber,
	}
	return strings.Join(parts, "\n")
}

// randomString generates a random string of specified length
func randomString(length int) string {
	const charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, length)
	rand.Read(b)
	for i := range b {
		b[i] = charset[int(b[i])%len(charset)]
	}
	return string(b)
}
