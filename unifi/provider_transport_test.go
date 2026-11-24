package unifi

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-log/tflogtest"
)

func TestProviderConnectionConfigPrecedence(t *testing.T) {
	t.Setenv("UNIFI_CLOUD_CONNECTOR", "true")
	t.Setenv("UNIFI_INSECURE", "true")
	t.Setenv("UNIFI_API_KEY", "")
	t.Setenv("UNIFI_USERNAME", "")
	t.Setenv("UNIFI_PASSWORD", "")
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"meta":{"rc":"ok","server_version":"10.0.0"}}`))
	}))
	defer server.Close()

	for _, tt := range []struct {
		name        string
		attributes  map[string]any
		wantError   string
		wantVersion bool
	}{
		{"explicit local and verified TLS", map[string]any{"cloud_connector": false, "allow_insecure": false}, "", false},
		{"explicit local and inherited TLS override", map[string]any{"cloud_connector": false}, "", true},
		{"unknown cloud mode", map[string]any{"cloud_connector": tfUnknown}, "Unknown connection mode", false},
		{"unknown TLS mode", map[string]any{"cloud_connector": false, "allow_insecure": tfUnknown}, "Unknown TLS verification setting", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var logs bytes.Buffer
			ctx := tflogtest.RootLogger(context.Background(), &logs)
			p := &unifiProvider{}
			var schema provider.SchemaResponse
			p.Schema(ctx, provider.SchemaRequest{}, &schema)
			tt.attributes["api_url"] = server.URL
			tt.attributes["api_key"] = "fixture-api-key"
			tt.attributes["username"] = "fixture-sensitive-username"
			raw := tfValue(t, schema.Schema.Type().TerraformType(ctx), tt.attributes)
			resp := &provider.ConfigureResponse{}
			p.Configure(ctx, provider.ConfigureRequest{Config: tfsdk.Config{Schema: schema.Schema, Raw: raw}}, resp)
			if strings.Contains(logs.String(), "fixture-sensitive-username") || strings.Contains(logs.String(), "fixture-api-key") {
				t.Fatal("authentication fields present in debug output")
			}
			if tt.wantError != "" {
				if !resp.Diagnostics.HasError() || resp.Diagnostics[0].Summary() != tt.wantError {
					t.Fatalf("expected %q, got %v", tt.wantError, resp.Diagnostics)
				}
				return
			}
			if resp.Diagnostics.HasError() {
				t.Fatal(resp.Diagnostics)
			}
			// SDK version discovery is best-effort: a rejected fixture certificate
			// produces an empty version. An explicitly allowed test certificate succeeds.
			if got := resp.ResourceData.(*Client).Version(); (got != "") != tt.wantVersion {
				t.Fatalf("version %q, want successful TLS request %v", got, tt.wantVersion)
			}
		})
	}
}
