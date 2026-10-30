package scanner

import (
	"log/slog"
	"slices"
	"strings"
)

type PortFilter func(status ScanStatus) bool

var SkipUnscannable PortFilter = func(status ScanStatus) bool {
	return status == StatusNoPorts || status == StatusLocalhostOnly || status == StatusNoTLS || status == StatusProbePort
}

var (
	readinessModernReady = "Endpoint offers TLS 1.3 and ML-KEM — ready for Modern profile"
	readinessNoPQC       = "Endpoint offers TLS 1.3 but no ML-KEM — not PQC ready"
	readinessTLS12Only   = "Endpoint only offers TLS 1.2 — will fail on Modern profile"
	readinessNoTLS       = "No TLS versions detected"
)

func PopulatePQCFields(pr *PortResult) {
	pr.TLS13Supported = slices.Contains(pr.TlsVersions, "TLSv1.3")

	if pr.TlsKeyExchange == nil {
		populateTLSReadiness(pr)
		return
	}

	if pr.TlsKeyExchange.ForwardSecrecy != nil {
		pr.MLKEMCiphers = pr.TlsKeyExchange.ForwardSecrecy.KEMs
		pr.MLKEMSupported = len(pr.MLKEMCiphers) > 0
	}

	seen := make(map[string]bool)
	for _, g := range pr.TlsKeyExchange.Groups {
		if groupProvidesKeyEncapsulation(g) && !seen[g] {
			pr.AllKEMs = append(pr.AllKEMs, g)
			seen[g] = true
		}
	}
	if pr.TlsKeyExchange.ForwardSecrecy != nil {
		for _, k := range pr.TlsKeyExchange.ForwardSecrecy.KEMs {
			if !seen[k] {
				pr.AllKEMs = append(pr.AllKEMs, k)
				seen[k] = true
			}
		}
	}

	populateTLSReadiness(pr)
}

// groupProvidesKeyEncapsulation returns true if we believe the group provided
// as an argument supports key encapsulation mechanism.
func groupProvidesKeyEncapsulation(group string) bool {
	return strings.Contains(strings.ToLower(group), "kem")
}

func populateTLSReadiness(pr *PortResult) {
	tls13 := pr.TLS13Supported
	tls12Only := !tls13 && len(pr.TlsVersions) > 0

	readiness := &TLSReadiness{
		TLS13Offered: tls13,
		TLS12Only:    tls12Only,
		PQCCapable:   pr.MLKEMSupported,
		MLKEMKEMs:    pr.MLKEMCiphers,
		AllKEMs:      pr.AllKEMs,
	}

	switch {
	case tls13 && pr.MLKEMSupported:
		readiness.Notes = readinessModernReady
	case tls13 && !pr.MLKEMSupported:
		readiness.Notes = readinessNoPQC
	case tls12Only:
		readiness.Notes = readinessTLS12Only
	case len(pr.TlsVersions) == 0:
		readiness.Notes = readinessNoTLS
	}

	pr.TLSReadiness = readiness
}

// CountPortsByStatus tallies port results by scan status across every IP.
func CountPortsByStatus(results ScanResults) map[ScanStatus]int {
	counts := make(map[ScanStatus]int)
	for _, ipResult := range results.IPResults {
		for _, portResult := range ipResult.PortResults {
			counts[portResult.Status]++
		}
	}
	return counts
}

// PQCSummary reports how many ports were actually probed for TLS, how many
// were skipped (and why), and how many probed ports meet each PQC criterion.
// Skipped ports were never tested, so they are excluded from all readiness
// counts rather than being reported as unsupported.
type PQCSummary struct {
	Scanned         int
	Skipped         int
	SkippedByStatus map[ScanStatus]int
	TLS13Ready      int
	MLKEMReady      int
	PQCReady        int
}

// SummarizePQC computes a PQCSummary using the standard SkipUnscannable filter
// so reported counts stay consistent with HasPQCComplianceFailures.
func SummarizePQC(results ScanResults) PQCSummary {
	summary := PQCSummary{SkippedByStatus: make(map[ScanStatus]int)}

	for status, count := range CountPortsByStatus(results) {
		if SkipUnscannable(status) {
			summary.Skipped += count
			summary.SkippedByStatus[status] = count
			continue
		}
		summary.Scanned += count
	}

	for _, ipResult := range results.IPResults {
		for _, portResult := range ipResult.PortResults {
			if SkipUnscannable(portResult.Status) {
				continue
			}
			if portResult.TLS13Supported {
				summary.TLS13Ready++
			}
			if portResult.MLKEMSupported {
				summary.MLKEMReady++
			}
			if portResult.TLS13Supported && portResult.MLKEMSupported {
				summary.PQCReady++
			}
		}
	}

	return summary
}

// hasPQCComplianceFailures is an unexported convenience wrapper used by tests
// that applies the standard SkipUnscannable filter.
func hasPQCComplianceFailures(results ScanResults) bool {
	return HasPQCComplianceFailures(results, SkipUnscannable)
}

func HasPQCComplianceFailures(results ScanResults, skip PortFilter) bool {
	for _, ipResult := range results.IPResults {
		for _, portResult := range ipResult.PortResults {
			if skip != nil && skip(portResult.Status) {
				continue
			}

			if !portResult.TLS13Supported {
				slog.Warn("PQC compliance failure: TLS 1.3 not supported", "ip", ipResult.IP, "port", portResult.Port)
				return true
			}

			if !portResult.MLKEMSupported {
				slog.Warn("PQC compliance failure: ML-KEM not supported", "ip", ipResult.IP, "port", portResult.Port)
				return true
			}

		}
	}
	return false
}
