package unifi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRejectedUpdatesOmitRequestValues(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if handleNewStyleSetup(w, r) {
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		if strings.HasSuffix(r.URL.Path, "/set/setting/snmp") {
			_, _ = w.Write([]byte(`{"code":"invalid","message":"invalid sample-community"}`))
		} else {
			_, _ = w.Write([]byte(`{"code":"invalid-setting"}`))
		}
	}))
	defer server.Close()

	ctx := context.Background()
	client, err := New(ctx, &Config{BaseURL: server.URL, APIKey: "fixture-key"})
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct{ path, detail string }{
		{"api/s/default/set/setting/snmp", "400"},
		{"api/s/default/set/setting/mgmt", "invalid-setting"},
	} {
		err := client.do(ctx, http.MethodPut, tt.path, map[string]string{"community": "sample-community"}, nil)
		if err == nil || !strings.Contains(err.Error(), tt.detail) || strings.Contains(err.Error(), "sample-community") {
			t.Fatalf("unexpected diagnostic for %s: %v", tt.path, err)
		}
	}
}
