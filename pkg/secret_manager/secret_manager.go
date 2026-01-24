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
	RefreshInterval int    `json:"refreshInterval"` // seconds, 0 = no auto-refresh

	// Device info for signature
	Platform    int    `json:"platform"`
	DeviceID    string `json:"deviceID"`
	Channel     string `json:"channel"`
	PackageName string `json:"packageName"`
	Version     string `json:"version"`
	Brand       string `json:"brand"`
	BuildNumber string `json:"buildNumber"`
}

// SecretManager manages fetching and refreshing secrets from Config Center
type SecretManager struct {
	config        *SecretConfig
	currentSecret string
	currentToken  string
	tokenExpiry   time.Time
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

// Start begins the secret manager, fetching initial secret and starting auto-refresh if configured
func (m *SecretManager) Start() error {
	// Fetch initial secret
	if err := m.RefreshNow(); err != nil {
		return fmt.Errorf("failed to fetch initial secret: %w", err)
	}

	// Start auto-refresh if interval is set
	if m.config.RefreshInterval > 0 {
		go m.autoRefreshLoop()
	}

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

// RefreshNow immediately fetches a new secret from Config Center
func (m *SecretManager) RefreshNow() error {
	// Fetch token first
	token, err := m.fetchToken()
	if err != nil {
		return fmt.Errorf("failed to fetch token: %w", err)
	}

	m.mu.Lock()
	m.currentToken = token
	m.mu.Unlock()

	// Fetch secret using the token
	secret, err := m.fetchSecret()
	if err != nil {
		return fmt.Errorf("failed to fetch secret: %w", err)
	}

	m.mu.Lock()
	oldSecret := m.currentSecret
	m.currentSecret = secret
	m.mu.Unlock()

	// Notify if secret changed
	if oldSecret != secret && m.OnSecretChanged != nil {
		m.OnSecretChanged(secret)
	}

	return nil
}

func (m *SecretManager) autoRefreshLoop() {
	ticker := time.NewTicker(time.Duration(m.config.RefreshInterval) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := m.RefreshNow(); err != nil {
				fmt.Printf("[SecretManager] Auto-refresh failed: %v\n", err)
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
func (m *SecretManager) fetchSecret() (string, error) {
	m.mu.RLock()
	token := m.currentToken
	m.mu.RUnlock()

	if token == "" {
		return "", fmt.Errorf("no token available")
	}

	// Generate Ed25519 keypair for this request
	publicKey, privateKey, err := GenerateEd25519Keypair()
	if err != nil {
		return "", fmt.Errorf("failed to generate keypair: %w", err)
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
		return "", fmt.Errorf("failed to sign payload: %w", err)
	}

	// Create HTTP request
	req, err := http.NewRequest(method, url, bytes.NewReader(bodyBytes))
	if err != nil {
		return "", err
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
		return "", err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	var result struct {
		Plaintext string `json:"plaintext"`
		ErrCode   int    `json:"errCode"`
		ErrMsg    string `json:"errMsg"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return "", fmt.Errorf("failed to parse response: %w", err)
	}

	if result.ErrCode != 0 {
		return "", fmt.Errorf("config center error: %d - %s", result.ErrCode, result.ErrMsg)
	}

	return result.Plaintext, nil
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
