package output

import (
	"fmt"
	"log/slog"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/openshift/tls-scanner/internal/k8s"
	"github.com/openshift/tls-scanner/internal/scanner"
)

const (
	// TLSPosturePredicateType identifies the unsigned TLS posture attestation payload.
	// CI (Prow/Konflux) signs this blob; the scanner does not embed signing keys.
	TLSPosturePredicateType = "https://github.com/openshift/tls-scanner/tls-posture/v1"

	attestationUnknownComponent = "unknown"

	PolicyBarPQC        = "pqc"
	PolicyBarTLSProfile = "tls-profile"
	PolicyBarObserve    = "observe"

	ComponentResultPass = "PASS"
	ComponentResultFail = "FAIL"
	ComponentResultSkip = "SKIP"

	OverallResultPass = "PASS"
	OverallResultFail = "FAIL"
)

// AttestationMeta carries build/runtime context embedded in the attestation payload.
type AttestationMeta struct {
	ScannerVersion string
	ScannerCommit  string
	ClusterVersion *k8s.ClusterVersionInfo
}

// TLSPostureAttestation is the unsigned attestation document written by --attestation-file.
// It is suitable for Cosign/in-toto signing by CI without further transformation of the
// predicate semantics.
type TLSPostureAttestation struct {
	PredicateType string              `json:"predicateType"`
	Predicate     TLSPosturePredicate `json:"predicate"`
}

// TLSPosturePredicate is the semantic claim: cluster/component TLS posture rollup.
type TLSPosturePredicate struct {
	ScannerVersion string                  `json:"scannerVersion"`
	ScannerCommit  string                  `json:"scannerCommit"`
	Timestamp      string                  `json:"timestamp"`
	PolicyBar      string                  `json:"policyBar"`
	Result         string                  `json:"result"`
	ClusterVersion *k8s.ClusterVersionInfo `json:"clusterVersion,omitempty"`
	Summary        TLSPostureSummary       `json:"summary"`
	Components     []ComponentPosture      `json:"components"`
}

// TLSPostureSummary is aggregate counts across components and ports.
type TLSPostureSummary struct {
	ComponentsTotal   int `json:"componentsTotal"`
	ComponentsPassed  int `json:"componentsPassed"`
	ComponentsFailed  int `json:"componentsFailed"`
	ComponentsSkipped int `json:"componentsSkipped"`
	PortsInScope      int `json:"portsInScope"`
	PortsSkipped      int `json:"portsSkipped"`
}

// ComponentPosture is the per-component rollup used by attestation consumers.
type ComponentPosture struct {
	Name           string              `json:"name"`
	Maintainer     string              `json:"maintainer,omitempty"`
	Result         string              `json:"result"`
	Successes      int                 `json:"successes"`
	Failures       int                 `json:"failures"`
	Skipped        int                 `json:"skipped"`
	Images         []string            `json:"images,omitempty"`
	FailureDetails []PortFailureDetail `json:"failureDetails,omitempty"`
}

// PortFailureDetail records why an in-scope port failed the active policy bar.
type PortFailureDetail struct {
	IP      string   `json:"ip"`
	Port    int      `json:"port"`
	Pod     string   `json:"pod,omitempty"`
	Reasons []string `json:"reasons"`
}

// BuildTLSPostureAttestation rolls ScanResults up by openshift component.
//
// In-scope ports are those not SkipUnscannable (NO_PORTS, LOCALHOST_ONLY, NO_TLS, PROBE_PORT).
// A component FAILs if any in-scope port fails the active policy bar; PASS if it has at least
// one in-scope success and no failures; SKIP if it only has skipped ports.
func BuildTLSPostureAttestation(results scanner.ScanResults, pqcCheck bool, meta AttestationMeta) TLSPostureAttestation {
	policyBar := PolicyBarObserve
	if pqcCheck {
		policyBar = PolicyBarPQC
	} else if scanner.TLSConfigComplianceFailuresEnforced(results) {
		policyBar = PolicyBarTLSProfile
	}

	type agg struct {
		name       string
		maintainer string
		successes  int
		failures   int
		skipped    int
		images     map[string]struct{}
		details    []PortFailureDetail
	}

	byComponent := make(map[string]*agg)
	portsInScope := 0
	portsSkipped := 0

	getAgg := func(ipResult scanner.IPResult) *agg {
		name := attestationUnknownComponent
		maintainer := ""
		if ipResult.OpenshiftComponent != nil {
			if ipResult.OpenshiftComponent.Component != "" {
				name = ipResult.OpenshiftComponent.Component
			}
			maintainer = ipResult.OpenshiftComponent.MaintainerComponent
		}
		a, ok := byComponent[name]
		if !ok {
			a = &agg{name: name, maintainer: maintainer, images: make(map[string]struct{})}
			byComponent[name] = a
		}
		if maintainer != "" && a.maintainer == "" {
			a.maintainer = maintainer
		}
		if ipResult.Pod != nil && ipResult.Pod.Image != "" {
			a.images[ipResult.Pod.Image] = struct{}{}
		}
		return a
	}

	for _, ipResult := range results.IPResults {
		a := getAgg(ipResult)
		podName := ""
		if ipResult.Pod != nil {
			podName = ipResult.Pod.Name
		}

		for _, portResult := range ipResult.PortResults {
			if scanner.SkipUnscannable(portResult.Status) {
				a.skipped++
				portsSkipped++
				continue
			}

			portsInScope++
			reasons := portFailureReasons(portResult, policyBar)
			if len(reasons) > 0 {
				a.failures++
				a.details = append(a.details, PortFailureDetail{
					IP:      ipResult.IP,
					Port:    portResult.Port,
					Pod:     podName,
					Reasons: reasons,
				})
				continue
			}
			a.successes++
		}
	}

	components := make([]ComponentPosture, 0, len(byComponent))
	summary := TLSPostureSummary{PortsInScope: portsInScope, PortsSkipped: portsSkipped}

	for _, a := range byComponent {
		cp := ComponentPosture{
			Name:           a.name,
			Maintainer:     a.maintainer,
			Successes:      a.successes,
			Failures:       a.failures,
			Skipped:        a.skipped,
			FailureDetails: a.details,
			Images:         sortedKeys(a.images),
		}
		switch {
		case a.failures > 0:
			cp.Result = ComponentResultFail
			summary.ComponentsFailed++
		case a.successes > 0:
			cp.Result = ComponentResultPass
			summary.ComponentsPassed++
		default:
			cp.Result = ComponentResultSkip
			summary.ComponentsSkipped++
		}
		summary.ComponentsTotal++
		components = append(components, cp)
	}

	sort.Slice(components, func(i, j int) bool {
		return components[i].Name < components[j].Name
	})

	overall := OverallResultPass
	if summary.ComponentsFailed > 0 {
		overall = OverallResultFail
	}
	// Observe mode never fails the overall result solely from missing PQC/profile —
	// portFailureReasons already returns no reasons for observe on successful scans.
	// If there were zero in-scope ports at all, still PASS (nothing to assert).

	ts := results.Timestamp
	if ts == "" {
		ts = time.Now().UTC().Format(time.RFC3339)
	}

	return TLSPostureAttestation{
		PredicateType: TLSPosturePredicateType,
		Predicate: TLSPosturePredicate{
			ScannerVersion: meta.ScannerVersion,
			ScannerCommit:  meta.ScannerCommit,
			Timestamp:      ts,
			PolicyBar:      policyBar,
			Result:         overall,
			ClusterVersion: meta.ClusterVersion,
			Summary:        summary,
			Components:     components,
		},
	}
}

func portFailureReasons(portResult scanner.PortResult, policyBar string) []string {
	var reasons []string
	switch policyBar {
	case PolicyBarPQC:
		if !portResult.TLS13Supported {
			reasons = append(reasons, "PQC: TLS 1.3 not supported")
		}
		if !portResult.MLKEMSupported {
			reasons = append(reasons, "PQC: ML-KEM not supported")
		}
	case PolicyBarTLSProfile:
		if portResult.IngressTLSConfigCompliance != nil && !scanner.IsTLSConfigCompliant(portResult.IngressTLSConfigCompliance) {
			reasons = append(reasons, "Ingress TLS config is not compliant")
		}
		if portResult.APIServerTLSConfigCompliance != nil && !scanner.IsTLSConfigCompliant(portResult.APIServerTLSConfigCompliance) {
			reasons = append(reasons, "API Server TLS config is not compliant")
		}
		if portResult.KubeletTLSConfigCompliance != nil && !scanner.IsTLSConfigCompliant(portResult.KubeletTLSConfigCompliance) {
			reasons = append(reasons, "Kubelet TLS config is not compliant")
		}
	case PolicyBarObserve:
		// Observational attestation: in-scope ports that scanned OK do not fail.
		// Still record hard scan errors on OK-status ports with Error set.
		if portResult.Status == scanner.StatusOK && portResult.Error != "" {
			reasons = append(reasons, "scan error: "+portResult.Error)
		}
	}
	return reasons
}

func sortedKeys(m map[string]struct{}) []string {
	if len(m) == 0 {
		return nil
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// WriteAttestationFile builds the TLS posture attestation and writes it as indented JSON.
func WriteAttestationFile(results scanner.ScanResults, filename string, pqcCheck bool, meta AttestationMeta) error {
	doc := BuildTLSPostureAttestation(results, pqcCheck, meta)
	if err := WriteJSONOutput(doc, filename); err != nil {
		return fmt.Errorf("write attestation: %w", err)
	}
	slog.Info("TLS posture attestation written",
		"path", filename,
		"policyBar", doc.Predicate.PolicyBar,
		"result", doc.Predicate.Result,
		"components", doc.Predicate.Summary.ComponentsTotal,
	)
	return nil
}

// resolveOutputPath joins artifactDir when filename is relative.
func resolveOutputPath(artifactDir, filename string) string {
	if filepath.IsAbs(filename) {
		return filename
	}
	return filepath.Join(artifactDir, filename)
}

// FormatAttestationSummary returns a one-line human summary for logs.
func FormatAttestationSummary(doc TLSPostureAttestation) string {
	s := doc.Predicate.Summary
	return fmt.Sprintf("result=%s policyBar=%s components=%d (pass=%d fail=%d skip=%d) portsInScope=%d",
		doc.Predicate.Result, doc.Predicate.PolicyBar, s.ComponentsTotal,
		s.ComponentsPassed, s.ComponentsFailed, s.ComponentsSkipped, s.PortsInScope)
}

// ComponentNames returns sorted component names (test helper / debugging).
func ComponentNames(doc TLSPostureAttestation) string {
	names := make([]string, 0, len(doc.Predicate.Components))
	for _, c := range doc.Predicate.Components {
		names = append(names, c.Name)
	}
	return strings.Join(names, ",")
}
