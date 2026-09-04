package scanner

import (
	"log/slog"

	"github.com/openshift/tls-scanner/internal/k8s"
)

// ComponentType identifies which TLS profile should be used when checking
// compliance for a scanned port.
type ComponentType int

const (
	// GenericComponent covers all components that have no override capability —
	// they must honor the cluster-wide APIServer TLS profile.
	GenericComponent ComponentType = iota
	// IngressComponent covers ports whose effective TLS profile is the
	// IngressController profile (with APIServer fallback when no override is set).
	IngressComponent
	// KubeletComponent covers ports whose effective TLS profile is the
	// KubeletConfig profile (with APIServer fallback when no override is set).
	KubeletComponent
	// ExemptComponent covers ports that are exempt from TLS profile compliance,
	// e.g. CI-only tooling injected into test clusters that is not part of the
	// product and has no mechanism to honor the cluster TLS profile. No
	// compliance result is populated, so the port is reported but never counts
	// as a failure.
	ExemptComponent
)

func getMinVersionValue(versions []string) int {
	if len(versions) == 0 {
		return 0
	}
	minVersion := TLSVersionValueMap[versions[0]]
	for _, v := range versions[1:] {
		verVal := TLSVersionValueMap[v]
		if verVal < minVersion {
			minVersion = verVal
		}
	}
	return minVersion
}

type profileInput struct {
	profileType     string
	minTLSVersion   string
	expectedCiphers []string
	result          *TLSConfigComplianceResult
}

func evaluateCompliance(scannedMinVer int, scannedCiphers []string, input profileInput) {
	input.result.ConfiguredProfile = input.profileType
	if input.minTLSVersion != "" {
		input.result.Version = scannedMinVer >= TLSVersionValueMap[input.minTLSVersion]
	} else {
		input.result.Version = true
	}
	input.result.Ciphers = checkCipherCompliance(scannedCiphers, input.expectedCiphers)
}

// CheckCompliance evaluates whether the port's observed TLS configuration
// honours the profile that applies to its component type:
//   - IngressComponent  → IngressController profile (or APIServer if no override)
//   - KubeletComponent  → KubeletConfig profile     (or APIServer if no override)
//   - ExemptComponent   → no check; all compliance results stay nil
//   - GenericComponent  → APIServer profile
//
// Only the relevant TLSConfigComplianceResult field on portResult is populated,
// leaving the others nil so callers never need to reason about which one to check.
func CheckCompliance(portResult *PortResult, tlsProfile *k8s.TLSSecurityProfile, componentType ComponentType) {
	scannedMinVer := 0
	if portResult.TlsVersions != nil {
		scannedMinVer = getMinVersionValue(portResult.TlsVersions)
	}

	switch componentType {
	case ExemptComponent:
		return
	case IngressComponent:
		if ing := tlsProfile.IngressController; ing != nil {
			portResult.IngressTLSConfigCompliance = &TLSConfigComplianceResult{}
			evaluateCompliance(scannedMinVer, portResult.TlsCiphers, profileInput{ing.Type, ing.MinTLSVersion, ing.Ciphers, portResult.IngressTLSConfigCompliance})
		}
	case KubeletComponent:
		if kube := tlsProfile.KubeletConfig; kube != nil {
			portResult.KubeletTLSConfigCompliance = &TLSConfigComplianceResult{}
			evaluateCompliance(scannedMinVer, portResult.TlsCiphers, profileInput{"", kube.MinTLSVersion, kube.TLSCipherSuites, portResult.KubeletTLSConfigCompliance})
		}
	default:
		if api := tlsProfile.APIServer; api != nil {
			portResult.APIServerTLSConfigCompliance = &TLSConfigComplianceResult{}
			evaluateCompliance(scannedMinVer, portResult.TlsCiphers, profileInput{api.Type, api.MinTLSVersion, api.Ciphers, portResult.APIServerTLSConfigCompliance})
		}
	}
}

// IsTLSConfigCompliant returns true when a compliance result exists and both
// the version and cipher checks passed.
func IsTLSConfigCompliant(result *TLSConfigComplianceResult) bool {
	return result != nil && result.Version && result.Ciphers
}

func checkCipherCompliance(gotCiphers []string, expectedCiphers []string) bool {
	if len(expectedCiphers) == 0 {
		return true
	}

	if len(gotCiphers) == 0 {
		return false
	}

	expectedSet := make(map[string]struct{}, len(expectedCiphers))
	for _, c := range expectedCiphers {
		expectedSet[c] = struct{}{}
	}

	for _, cipher := range gotCiphers {
		converted, ok := IanaCipherToOpenSSLCipherMap[cipher]
		if !ok {
			// If the cipher is not in the map, try to use the original cipher,
			// testssl.sh may report them in IANA format (e.g. in cipher-tls1_* ciphers)
			converted = cipher
		}
		if _, exists := expectedSet[converted]; !exists {
			slog.Warn("cipher not found in expected cipher set, compliance will fail", "cipher", cipher, "resolved", converted)
			return false
		}
	}

	return true
}

// TLSConfigComplianceFailuresEnforced is true when the cluster has opted into
// strict TLS profile adherence (tlsAdherence: StrictAllComponents); only then
// do TLSConfigCompliance mismatches affect exit code and JUnit failures.
func TLSConfigComplianceFailuresEnforced(results ScanResults) bool {
	if results.TLSSecurityConfig == nil {
		return false
	}
	return k8s.EnforceTLSConfigComplianceFailures(results.TLSSecurityConfig.TLSAdherence)
}

func HasComplianceFailures(results ScanResults) bool {
	if !TLSConfigComplianceFailuresEnforced(results) {
		return false
	}
	for _, ipResult := range results.IPResults {
		for _, portResult := range ipResult.PortResults {
			if portResult.IngressTLSConfigCompliance != nil && !IsTLSConfigCompliant(portResult.IngressTLSConfigCompliance) {
				return true
			}
			if portResult.APIServerTLSConfigCompliance != nil && !IsTLSConfigCompliant(portResult.APIServerTLSConfigCompliance) {
				return true
			}
			if portResult.KubeletTLSConfigCompliance != nil && !IsTLSConfigCompliant(portResult.KubeletTLSConfigCompliance) {
				return true
			}
		}
	}
	return false
}
