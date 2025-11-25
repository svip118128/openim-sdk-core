package network

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/openimsdk/openim-sdk-core/v3/pkg/ccontext"
	"github.com/openimsdk/openim-sdk-core/v3/sdk_struct"
)

func TestName(t *testing.T) {
	var conf ccontext.GlobalConfig
	conf.IMConfig = &sdk_struct.IMConfig{
		ApiAddr: "http://127.0.0.1:8080",
	}
	ctx := ccontext.WithInfo(context.Background(), &conf)
	ctx = ccontext.WithOperationID(ctx, "123456")
	var resp any
	if err := ApiPost(ctx, "/test", map[string]any{}, &resp); err != nil {
		t.Log(err)
		return
	}
	t.Log("success")
}

func TestApiPostCustomHeaders(t *testing.T) {
	var received http.Header
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received = r.Header.Clone()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"errCode":0,"errMsg":"","errDlt":"","data":null}`))
	}))
	defer server.Close()

	conf := &ccontext.GlobalConfig{
		Token: "token-value",
		IMConfig: &sdk_struct.IMConfig{
			ApiAddr: server.URL,
		},
		CustomHTTPHeader: map[string]string{
			"Authorization": "Bearer demo",
			"X-Signature":   "sig-demo",
			"X-Timestamp":   "ts-demo",
			"X-Nonce":       "nonce-demo",
		},
	}
	ctx := ccontext.WithInfo(context.Background(), conf)
	ctx = ccontext.WithOperationID(ctx, "op-123")

	var resp any
	if err := ApiPost(ctx, "/custom", map[string]any{}, &resp); err != nil {
		t.Fatalf("ApiPost failed: %v", err)
	}

	if received.Get("Authorization") != "Bearer demo" {
		t.Fatalf("Authorization header mismatch: %v", received.Get("Authorization"))
	}
	if received.Get("X-Signature") != "sig-demo" {
		t.Fatalf("X-Signature header mismatch: %v", received.Get("X-Signature"))
	}
	if received.Get("X-Nonce") != "nonce-demo" {
		t.Fatalf("X-Nonce header mismatch: %v", received.Get("X-Nonce"))
	}
	if received.Get("token") != "token-value" {
		t.Fatalf("token header should remain unchanged, got: %v", received.Get("token"))
	}
	if received.Get("operationID") != "op-123" {
		t.Fatalf("operationID header should remain unchanged, got: %v", received.Get("operationID"))
	}
}
