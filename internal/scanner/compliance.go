package scanner

import (
	"log"

	"github.com/openshift/tls-scanner/internal/k8s"
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

func CheckCompliance(portResult *PortResult, tlsProfile *k8s.TLSSecurityProfile) {
	scannedMinVer := 0
	if portResult.TlsVersions != nil {
		scannedMinVer = getMinVersionValue(portResult.TlsVersions)
	}

	portResult.IngressTLSConfigCompliance = &TLSConfigComplianceResult{}
	portResult.APIServerTLSConfigCompliance = &TLSConfigComplianceResult{}
	portResult.KubeletTLSConfigCompliance = &TLSConfigComplianceResult{}

	var profiles []profileInput

	if ing := tlsProfile.IngressController; ing != nil {
		profiles = append(profiles, profileInput{ing.Type, ing.MinTLSVersion, ing.Ciphers, portResult.IngressTLSConfigCompliance})
	}
	if api := tlsProfile.APIServer; api != nil {
		profiles = append(profiles, profileInput{api.Type, api.MinTLSVersion, api.Ciphers, portResult.APIServerTLSConfigCompliance})
	}
	if kube := tlsProfile.KubeletConfig; kube != nil {
		profiles = append(profiles, profileInput{"", kube.MinTLSVersion, kube.TLSCipherSuites, portResult.KubeletTLSConfigCompliance})
	}

	for _, p := range profiles {
		evaluateCompliance(scannedMinVer, portResult.TlsCiphers, p)
	}
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
			log.Printf("Warning: cipher %q (resolved as %q) not found in expected cipher set. cipher compliance will fail.", cipher, converted)
			return false
		}
	}

	return true
}

func HasComplianceFailures(results ScanResults) bool {
	for _, ipResult := range results.IPResults {
		for _, portResult := range ipResult.PortResults {
			if portResult.IngressTLSConfigCompliance != nil &&
				(!portResult.IngressTLSConfigCompliance.Version || !portResult.IngressTLSConfigCompliance.Ciphers) {
				return true
			}
			if portResult.APIServerTLSConfigCompliance != nil &&
				(!portResult.APIServerTLSConfigCompliance.Version || !portResult.APIServerTLSConfigCompliance.Ciphers) {
				return true
			}
			if portResult.KubeletTLSConfigCompliance != nil &&
				(!portResult.KubeletTLSConfigCompliance.Version || !portResult.KubeletTLSConfigCompliance.Ciphers) {
				return true
			}
		}
	}
	return false
}
