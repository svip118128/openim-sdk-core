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

// Start begins the secret manager.
func (m *SecretManager) Start() error {
	fmt.Println("[SecretManager] Starting...")
	// Fetch initial secret (blocking)
	if _, err := m.RefreshNow(); err != nil {
		fmt.Printf("[SecretManager] Start failed: %v\n", err)
		return fmt.Errorf("failed to fetch initial secret: %w", err)
	}

	// Always start refresh loop for auto-renewal based on expiry
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
	fmt.Println("[SecretManager] RefreshNow called")
	// Fetch token first
	token, err := m.fetchToken()
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to fetch token: %w", err)
	}
	fmt.Printf("[SecretManager] Token fetched successfully (len=%d)\n", len(token))

	m.mu.Lock()
	m.currentToken = token
	m.mu.Unlock()

	// Fetch secret using the token
	secret, expireAt, err := m.fetchSecret()
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to fetch secret: %w", err)
	}
	fmt.Printf("[SecretManager] Secret fetched successfully (len=%d)\n", len(secret))

	m.mu.Lock()
	oldSecret := m.currentSecret
	m.currentSecret = secret
	m.mu.Unlock()

	// Notify if secret changed
	if oldSecret != secret && m.OnSecretChanged != nil {
		fmt.Println("[SecretManager] Secret changed, notifying listener")
		m.OnSecretChanged(secret)
	}

	// Calculate next refresh time
	// Refresh exactly at expiration or slightly after?
	// So we schedule refresh at expireAtTime.
	now := time.Now()
	if !expireAt.IsZero() && expireAt.After(now) {
		// Calculate precise duration until expiry
		refreshIn := expireAt.Sub(now)
		fmt.Printf("[SecretManager] Scheduled refresh in %v (at %v)\n", refreshIn, expireAt)
		m.mu.Lock()
		m.nextRefresh = expireAt
		m.mu.Unlock()
		return expireAt, nil
	}

	return time.Time{}, fmt.Errorf("no expiry time provided")
}

func (m *SecretManager) refreshLoop() {
	// Initial fetch was done in Start

	for {
		m.mu.RLock()
		next := m.nextRefresh
		m.mu.RUnlock()

		if next.IsZero() {
			fmt.Println("[SecretManager] No expiry time known. Auto-refresh paused until error or manual refresh.")
			select {
			case <-m.stopChan:
				return
			}
		}

		waitDuration := time.Until(next)
		if waitDuration < 0 {
			waitDuration = 0 // Should trigger immediately if past
		}

		timer := time.NewTimer(waitDuration)

		select {
		case <-timer.C:
			// Time to refresh
			newNext, err := m.RefreshNow()
			timer.Stop()

			if err != nil {
				fmt.Printf("[SecretManager] Refresh failed: %v. Retrying in 30s...\n", err)
				// Retry in 30s on failure?
				m.mu.Lock()
				m.nextRefresh = time.Now().Add(30 * time.Second)
				m.mu.Unlock()
			} else {
				m.mu.Lock()
				m.nextRefresh = newNext
				m.mu.Unlock()
				fmt.Printf("[SecretManager] Secret refreshed. Next refresh at: %v\n", newNext)
			}

		case <-m.stopChan:
			timer.Stop()
			return
		}
	}
}

// fetchToken fetches a new token from Config Center using Ed25519 signature
func (m *SecretManager) fetchToken() (string, error) {
	fmt.Println("[SecretManager] Generating Ed25519 keypair for token...")
	// Generate Ed25519 keypair
	publicKey, privateKey, err := GenerateEd25519Keypair()
	if err != nil {
		return "", fmt.Errorf("failed to generate keypair: %w", err)
	}

	// Build request
	url := strings.TrimSuffix(m.config.ConfigCenterURL, "/") + "/v2/auth/get_token"
	method := "POST"
	path := "/v2/auth/get_token"

	publicKeyHex := hex.EncodeToString(publicKey)
	body := map[string]interface{}{
		"publicKey": publicKeyHex,
	}
	bodyBytes, _ := json.Marshal(body)

	// Generate signature
	timestamp := time.Now().UTC().Format(time.RFC3339Nano)
	nonce := randomString(32)
	operationID := uuid.New().String()

	payload := BuildTokenPayload(method, path, timestamp, nonce, operationID, bodyBytes, DeviceInfo{
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

	fmt.Printf("[SecretManager] Fetching token from %s\n", url)
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
	fmt.Printf("[SecretManager] Token response status: %d, body: %s\n", resp.StatusCode, string(respBody))

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
	fmt.Println("[SecretManager] Fetching secret...")
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
	path := fmt.Sprintf("/v2/namespaces/%s/secrets/%s:get", m.config.Namespace, m.config.SecretName)
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

	payload := BuildTokenPayload(method, path, timestamp, nonce, operationID, bodyBytes, DeviceInfo{
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

	fmt.Printf("[SecretManager] Fetching secret from %s\n", url)
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
	fmt.Printf("[SecretManager] Secret response status: %d, body: %s\n", resp.StatusCode, string(respBody))

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
	} else if len(result.ExpireAtMap) > 0 {
		// Try to find expiry in the map
		// Priority: "expireAt", "expiresAt", or check for the secret name key
		if val, ok := result.ExpireAtMap["expireAt"]; ok {
			expireAtTime = parseExpiry(val)
		} else if val, ok := result.ExpireAtMap["expiresAt"]; ok {
			expireAtTime = parseExpiry(val)
		} else if val, ok := result.ExpireAtMap[m.config.SecretName]; ok {
			expireAtTime = parseExpiry(val)
		}
	}

	return result.Plaintext, expireAtTime, nil
}

func parseExpiry(val interface{}) time.Time {
	switch v := val.(type) {
	case float64:
		return time.Unix(int64(v), 0)
	case int64:
		return time.Unix(v, 0)
	case string:
		// Try parsing RFC3339
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			return t
		}
		// Try parsing RFC3339Nano
		if t, err := time.Parse(time.RFC3339Nano, v); err == nil {
			return t
		}
		// Try other common formats if needed
	}
	return time.Time{}
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
func BuildTokenPayload(method, path, timestamp, nonce, operationID string, body []byte, info DeviceInfo) string {
	parts := []string{
		strings.ToUpper(method),
		path,
		timestamp,
		nonce,
		string(body),
		fmt.Sprintf("%d", info.Platform),
		operationID,
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
