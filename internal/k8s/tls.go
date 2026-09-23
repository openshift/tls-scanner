package k8s

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	configv1 "github.com/openshift/api/config/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var (
	defaultProfileName    = "Default"
	defaultProfileType    = configv1.TLSProfileIntermediateType
	defaultProfileCiphers = configv1.TLSProfiles[defaultProfileType].Ciphers
	defaultProfileMinVer  = string(configv1.TLSProfiles[defaultProfileType].MinTLSVersion)
)

func (c *Client) GetTLSSecurityProfile() (*TLSSecurityProfile, error) {
	slog.Info("Collecting TLS security profiles from OpenShift components...")

	profile := &TLSSecurityProfile{}

	// APIServer is fetched first — it is the cluster-wide default that Ingress and
	// Kubelet inherit when no component-specific override is configured.
	apiserver, err := c.configClient.ConfigV1().APIServers().Get(context.Background(), "cluster", metav1.GetOptions{})
	if err != nil {
		slog.Warn("could not get API Server custom resource", "error", err)
		profile.TLSAdherence = configv1.TLSAdherencePolicyNoOpinion
	} else {
		profile.APIServer = extractAPIServerTLS(apiserver)
		profile.TLSAdherence = apiserver.Spec.TLSAdherence
	}

	if ingressTLS, err := c.getIngressControllerTLS(profile.APIServer); err != nil {
		slog.Warn("could not get Ingress Controller TLS config", "error", err)
	} else {
		profile.IngressController = ingressTLS
	}

	if kubeletTLS, err := c.getKubeletTLS(profile.APIServer); err != nil {
		slog.Warn("could not get Kubelet TLS config", "error", err)
	} else {
		profile.KubeletConfig = kubeletTLS
	}

	return profile, nil
}

func resolvePredefinedProfile(profileType configv1.TLSProfileType) ([]string, string, bool) {
	predefined, ok := configv1.TLSProfiles[profileType]
	if !ok {
		return nil, "", false
	}
	return predefined.Ciphers, string(predefined.MinTLSVersion), true
}

func (c *Client) getIngressControllerTLS(fallback *APIServerTLSProfile) (*IngressTLSProfile, error) {
	ingress, err := c.operatorClient.OperatorV1().IngressControllers("openshift-ingress-operator").Get(context.Background(), "default", metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get IngressController custom resource: %w", err)
	}

	profile := &IngressTLSProfile{}

	if ingress.Spec.TLSSecurityProfile == nil {
		// No explicit override: inherit the cluster-wide APIServer profile.
		if fallback != nil {
			profile.Type = fallback.Type
			profile.Ciphers = fallback.Ciphers
			profile.MinTLSVersion = fallback.MinTLSVersion
		} else {
			profile.Type = defaultProfileName
			profile.Ciphers = defaultProfileCiphers
			profile.MinTLSVersion = defaultProfileMinVer
		}
		return profile, nil
	}

	profile.Type = string(ingress.Spec.TLSSecurityProfile.Type)
	if custom := ingress.Spec.TLSSecurityProfile.Custom; custom != nil {
		profile.Ciphers = custom.Ciphers
		profile.MinTLSVersion = string(custom.MinTLSVersion)
		return profile, nil
	}
	if ciphers, minVer, ok := resolvePredefinedProfile(ingress.Spec.TLSSecurityProfile.Type); ok {
		profile.Ciphers = ciphers
		profile.MinTLSVersion = minVer
	}

	return profile, nil
}

func extractAPIServerTLS(apiserver *configv1.APIServer) *APIServerTLSProfile {
	profile := &APIServerTLSProfile{}

	if apiserver.Spec.TLSSecurityProfile == nil {
		profile.Type = defaultProfileName
		profile.Ciphers = defaultProfileCiphers
		profile.MinTLSVersion = defaultProfileMinVer
		return profile
	}

	profile.Type = string(apiserver.Spec.TLSSecurityProfile.Type)
	if custom := apiserver.Spec.TLSSecurityProfile.Custom; custom != nil {
		profile.Ciphers = custom.Ciphers
		profile.MinTLSVersion = string(custom.MinTLSVersion)
		return profile
	}
	if ciphers, minVer, ok := resolvePredefinedProfile(apiserver.Spec.TLSSecurityProfile.Type); ok {
		profile.Ciphers = ciphers
		profile.MinTLSVersion = minVer
	}

	return profile
}

func (c *Client) getKubeletTLS(fallback *APIServerTLSProfile) (*KubeletTLSProfile, error) {
	kubeletConfigs, err := c.mcfgClient.MachineconfigurationV1().KubeletConfigs().List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list KubeletConfigs: %w", err)
	}

	for _, kc := range kubeletConfigs.Items {
		if kc.Spec.TLSSecurityProfile != nil {
			profile := &KubeletTLSProfile{}
			tlsProfile := kc.Spec.TLSSecurityProfile

			if tlsProfile.Type == configv1.TLSProfileCustomType {
				if custom := tlsProfile.Custom; custom != nil {
					profile.TLSCipherSuites = custom.Ciphers
					profile.MinTLSVersion = string(custom.MinTLSVersion)
				}
			} else if ciphers, minVer, ok := resolvePredefinedProfile(tlsProfile.Type); ok {
				profile.TLSCipherSuites = ciphers
				profile.MinTLSVersion = minVer
			}
			return profile, nil
		}
	}

	// No explicit KubeletConfig override: inherit the cluster-wide APIServer profile.
	if fallback != nil {
		return &KubeletTLSProfile{
			TLSCipherSuites: fallback.Ciphers,
			MinTLSVersion:   fallback.MinTLSVersion,
		}, nil
	}

	return nil, fmt.Errorf("no KubeletConfig with a TLSSecurityProfile found in the cluster")
}

// NewTLSSecurityProfileFromType builds a TLSSecurityProfile from a predefined
// OpenShift TLS profile type (Old, Intermediate, Modern). Components without an
// explicit override inherit the APIServer profile, matching standalone OpenShift
// behavior. Used when the cluster APIServer CR does not reflect the effective
// profile, such as HyperShift hosted control planes.
//
// TLSAdherence is set to StrictAllComponents because explicitly supplying a
// profile on the CLI is an unambiguous opt-in to enforcement — compliance
// failures must be reported regardless of the cluster's tlsAdherence setting.
func NewTLSSecurityProfileFromType(profileType string) (*TLSSecurityProfile, error) {
	var normalized configv1.TLSProfileType
	switch strings.ToLower(strings.TrimSpace(profileType)) {
	case "old":
		normalized = configv1.TLSProfileOldType
	case "intermediate":
		normalized = configv1.TLSProfileIntermediateType
	case "modern":
		normalized = configv1.TLSProfileModernType
	default:
		return nil, fmt.Errorf("unsupported TLS profile type %q (supported: Old, Intermediate, Modern)", profileType)
	}

	predefined := configv1.TLSProfiles[normalized]
	apiServer := &APIServerTLSProfile{
		Type:          string(normalized),
		Ciphers:       predefined.Ciphers,
		MinTLSVersion: string(predefined.MinTLSVersion),
	}

	return &TLSSecurityProfile{
		TLSAdherence: configv1.TLSAdherencePolicyStrictAllComponents,
		APIServer:    apiServer,
		IngressController: &IngressTLSProfile{
			Type:          apiServer.Type,
			Ciphers:       apiServer.Ciphers,
			MinTLSVersion: apiServer.MinTLSVersion,
		},
		KubeletConfig: &KubeletTLSProfile{
			TLSCipherSuites: apiServer.Ciphers,
			MinTLSVersion:   apiServer.MinTLSVersion,
		},
	}, nil
}
