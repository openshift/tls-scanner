package k8s

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	configv1 "github.com/openshift/api/config/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

const defaultHostedClusterNamespace = "clusters"

var hostedClusterGVR = schema.GroupVersionResource{
	Group:    "hypershift.openshift.io",
	Version:  "v1beta1",
	Resource: "hostedclusters",
}

// GetTLSSecurityProfileFromHostedCluster loads the expected TLS profile from a
// HyperShift HostedCluster on the management cluster. HCP workloads (kube-apiserver,
// etcd, oauth-openshift) run on the management cluster but inherit TLS settings
// from HostedCluster.spec.configuration, not from the management APIServer CR.
func (c *Client) GetTLSSecurityProfileFromHostedCluster(name, namespace string) (*TLSSecurityProfile, error) {
	if namespace == "" {
		namespace = defaultHostedClusterNamespace
	}

	slog.Info("loading TLS security profile from HostedCluster", "name", name, "namespace", namespace)

	obj, err := c.dynamicClient.Resource(hostedClusterGVR).Namespace(namespace).Get(context.Background(), name, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("get HostedCluster %s/%s: %w", namespace, name, err)
	}

	apiServerSpec, err := extractHostedClusterAPIServerSpec(obj)
	if err != nil {
		return nil, err
	}

	profile := TLSSecurityProfileFromAPIServerSpec(apiServerSpec)
	if profile.APIServer != nil {
		slog.Info("loaded TLS profile from HostedCluster",
			"name", name,
			"namespace", namespace,
			"type", profile.APIServer.Type,
			"minTLSVersion", profile.APIServer.MinTLSVersion,
		)
	}

	return profile, nil
}

func extractHostedClusterAPIServerSpec(obj *unstructured.Unstructured) (*configv1.APIServerSpec, error) {
	raw, found, err := unstructured.NestedMap(obj.Object, "spec", "configuration", "apiServer")
	if err != nil {
		return nil, fmt.Errorf("read HostedCluster configuration.apiServer: %w", err)
	}
	if !found || len(raw) == 0 {
		slog.Warn("HostedCluster has no configuration.apiServer; using default TLS profile")
		return &configv1.APIServerSpec{}, nil
	}

	data, err := json.Marshal(raw)
	if err != nil {
		return nil, fmt.Errorf("marshal HostedCluster configuration.apiServer: %w", err)
	}

	spec := &configv1.APIServerSpec{}
	if err := json.Unmarshal(data, spec); err != nil {
		return nil, fmt.Errorf("unmarshal HostedCluster configuration.apiServer: %w", err)
	}

	return spec, nil
}

// TLSSecurityProfileFromAPIServerSpec builds a cluster TLS profile from an
// APIServerSpec, propagating the APIServer profile to ingress and kubelet the
// same way standalone OpenShift does when no component override exists.
func TLSSecurityProfileFromAPIServerSpec(spec *configv1.APIServerSpec) *TLSSecurityProfile {
	if spec == nil {
		spec = &configv1.APIServerSpec{}
	}

	apiServer := extractAPIServerTLSFromSpec(spec)
	return &TLSSecurityProfile{
		APIServer: apiServer,
		IngressController: &IngressTLSProfile{
			Type:          apiServer.Type,
			Ciphers:       apiServer.Ciphers,
			MinTLSVersion: apiServer.MinTLSVersion,
		},
		KubeletConfig: &KubeletTLSProfile{
			TLSCipherSuites: apiServer.Ciphers,
			MinTLSVersion:   apiServer.MinTLSVersion,
		},
	}
}
