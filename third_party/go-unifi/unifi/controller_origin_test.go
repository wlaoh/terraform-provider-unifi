package unifi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestControllerURL(t *testing.T) {
	for _, tt := range []struct {
		raw   string
		valid bool
	}{
		{"https://gateway.example:8443", true}, {"http://gateway.example", false},
		{"http://127.0.0.1:8443", true}, {"http://[::1]:8443", true},
		{"http://localhost:8443", true}, {"http://localhost.example", false},
		{"https://user:password@gateway.example", false}, {"https://gateway.example?auth=ignored", false},
		{"gateway.example:8443", false},
	} {
		var c ApiClient
		if err := c.setBaseURL(tt.raw); (err == nil) != tt.valid {
			t.Errorf("URL %q: %v", tt.raw, err)
		}
	}
}

func TestControllerRedirectPolicy(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handleNewStyleSetup(w, r)
	}))
	defer server.Close()
	client, err := New(context.Background(), &Config{BaseURL: server.URL, APIKey: "fixture"})
	if err != nil {
		t.Fatal(err)
	}

	origin, err := http.NewRequest(http.MethodGet, "https://gateway.example/status", nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		target  string
		allowed bool
	}{
		{"https://gateway.example/api", true}, {"https://GATEWAY.example:443/api", true},
		{"https://other.example/api", false}, {"https://gateway.example:9443/api", false},
		{"http://gateway.example/api", false}, {"https://user@gateway.example/api", false},
	} {
		target, err := http.NewRequest(http.MethodGet, tt.target, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := client.c.HTTPClient.CheckRedirect(target, []*http.Request{origin}); (err == nil) != tt.allowed {
			t.Errorf("redirect to %q: %v", tt.target, err)
		}
	}
}
