package k8s

import (
	"testing"

	configv1 "github.com/openshift/api/config/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func TestTLSSecurityProfileFromAPIServerSpec(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		spec            *configv1.APIServerSpec
		wantType        string
		wantMinTLS      string
		wantIngressType string
	}{
		{
			name:            "nil spec uses default",
			spec:            nil,
			wantType:        "Default",
			wantIngressType: "Default",
		},
		{
			name: "modern profile",
			spec: &configv1.APIServerSpec{
				TLSSecurityProfile: &configv1.TLSSecurityProfile{
					Type: configv1.TLSProfileModernType,
				},
			},
			wantType:        "Modern",
			wantMinTLS:      string(configv1.TLSProfiles[configv1.TLSProfileModernType].MinTLSVersion),
			wantIngressType: "Modern",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := TLSSecurityProfileFromAPIServerSpec(tt.spec)
			if got.APIServer.Type != tt.wantType {
				t.Errorf("APIServer.Type = %q, want %q", got.APIServer.Type, tt.wantType)
			}
			if got.IngressController.Type != tt.wantIngressType {
				t.Errorf("IngressController.Type = %q, want %q", got.IngressController.Type, tt.wantIngressType)
			}
			if tt.wantMinTLS != "" && got.APIServer.MinTLSVersion != tt.wantMinTLS {
				t.Errorf("APIServer.MinTLSVersion = %q, want %q", got.APIServer.MinTLSVersion, tt.wantMinTLS)
			}
		})
	}
}

func TestExtractHostedClusterAPIServerSpec(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		object      map[string]any
		wantType    string
		wantDefault bool
	}{
		{
			name:        "missing configuration uses default",
			object:      map[string]any{"spec": map[string]any{}},
			wantDefault: true,
		},
		{
			name: "modern hosted cluster configuration",
			object: map[string]any{
				"spec": map[string]any{
					"configuration": map[string]any{
						"apiServer": map[string]any{
							"tlsSecurityProfile": map[string]any{
								"type":   "Modern",
								"modern": map[string]any{},
							},
						},
					},
				},
			},
			wantType: "Modern",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			spec, err := extractHostedClusterAPIServerSpec(&unstructured.Unstructured{Object: tt.object})
			if err != nil {
				t.Fatalf("extractHostedClusterAPIServerSpec() error = %v", err)
			}

			profile := TLSSecurityProfileFromAPIServerSpec(spec)
			if tt.wantDefault {
				if profile.APIServer.Type != "Default" {
					t.Errorf("APIServer.Type = %q, want Default", profile.APIServer.Type)
				}
				return
			}
			if profile.APIServer.Type != tt.wantType {
				t.Errorf("APIServer.Type = %q, want %q", profile.APIServer.Type, tt.wantType)
			}
		})
	}
}
