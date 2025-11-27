package network

import (
	"net/http"
	"testing"
)

func TestApplyCustomHeaders(t *testing.T) {
	header := http.Header{}
	jsonStr := `{"Authorization":"Bearer demo","X-Signature":"sig-demo","X-Nonce":"nonce-demo","X-Unknown":"ignore","X-Timestamp":""}`

	if err := ApplyCustomHeaders(header, jsonStr); err != nil {
		t.Fatalf("ApplyCustomHeaders returned error: %v", err)
	}

	if got := header.Get("Authorization"); got != "Bearer demo" {
		t.Fatalf("Authorization mismatch, got %q", got)
	}
	if got := header.Get("X-Signature"); got != "sig-demo" {
		t.Fatalf("X-Signature mismatch, got %q", got)
	}
	if got := header.Get("X-Nonce"); got != "nonce-demo" {
		t.Fatalf("X-Nonce mismatch, got %q", got)
	}
	if got := header.Get("X-Unknown"); got != "" {
		t.Fatalf("unexpected header X-Unknown set to %q", got)
	}
	if got := header.Get("X-Timestamp"); got != "" {
		t.Fatalf("empty value should be ignored, got %q", got)
	}
}

func TestApplyCustomHeadersInvalidJSON(t *testing.T) {
	if err := ApplyCustomHeaders(http.Header{}, "{invalid"); err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}
