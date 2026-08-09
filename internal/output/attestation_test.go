package output

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	configv1 "github.com/openshift/api/config/v1"

	"github.com/openshift/tls-scanner/internal/k8s"
	"github.com/openshift/tls-scanner/internal/scanner"
)

func TestBuildTLSPostureAttestationPQCRollup(t *testing.T) {
	t.Parallel()

	results := scanner.ScanResults{
		Timestamp: "2026-07-23T12:00:00Z",
		IPResults: []scanner.IPResult{
			{
				IP: "10.0.0.1",
				OpenshiftComponent: &k8s.OpenshiftComponent{
					Component:           "kube-apiserver",
					MaintainerComponent: "ocp",
				},
				Pod: &k8s.PodInfo{Name: "apiserver", Image: "quay.io/openshift/kube-apiserver@sha256:aaa"},
				PortResults: []scanner.PortResult{
					{
						Port:           6443,
						Status:         scanner.StatusOK,
						TLS13Supported: true,
						MLKEMSupported: true,
					},
					{
						Port:   8080,
						Status: scanner.StatusLocalhostOnly,
					},
				},
			},
			{
				IP: "10.0.0.2",
				OpenshiftComponent: &k8s.OpenshiftComponent{
					Component: "openshift-ingress",
				},
				Pod: &k8s.PodInfo{Name: "router", Image: "quay.io/openshift/router@sha256:bbb"},
				PortResults: []scanner.PortResult{
					{
						Port:           443,
						Status:         scanner.StatusOK,
						TLS13Supported: true,
						MLKEMSupported: false,
					},
				},
			},
			{
				IP: "10.0.0.3",
				PortResults: []scanner.PortResult{
					{Port: 9090, Status: scanner.StatusNoTLS},
				},
			},
		},
	}

	doc := BuildTLSPostureAttestation(results, true, AttestationMeta{
		ScannerVersion: "test",
		ScannerCommit:  "abc",
		ClusterVersion: &k8s.ClusterVersionInfo{Version: "4.22.0", Image: "quay.io/ocp@sha256:ccc"},
	})

	if doc.PredicateType != TLSPosturePredicateType {
		t.Errorf("PredicateType = %q", doc.PredicateType)
	}
	if doc.Predicate.PolicyBar != PolicyBarPQC {
		t.Errorf("PolicyBar = %q, want %q", doc.Predicate.PolicyBar, PolicyBarPQC)
	}
	if doc.Predicate.Result != OverallResultFail {
		t.Errorf("Result = %q, want FAIL", doc.Predicate.Result)
	}
	if doc.Predicate.ClusterVersion == nil || doc.Predicate.ClusterVersion.Version != "4.22.0" {
		t.Errorf("ClusterVersion = %+v", doc.Predicate.ClusterVersion)
	}
	if doc.Predicate.Summary.ComponentsTotal != 3 {
		t.Errorf("ComponentsTotal = %d, want 3", doc.Predicate.Summary.ComponentsTotal)
	}
	if doc.Predicate.Summary.ComponentsPassed != 1 || doc.Predicate.Summary.ComponentsFailed != 1 || doc.Predicate.Summary.ComponentsSkipped != 1 {
		t.Errorf("summary pass/fail/skip = %d/%d/%d, want 1/1/1",
			doc.Predicate.Summary.ComponentsPassed, doc.Predicate.Summary.ComponentsFailed, doc.Predicate.Summary.ComponentsSkipped)
	}

	byName := map[string]ComponentPosture{}
	for _, c := range doc.Predicate.Components {
		byName[c.Name] = c
	}

	api := byName["kube-apiserver"]
	if api.Result != ComponentResultPass || api.Successes != 1 || api.Skipped != 1 {
		t.Errorf("kube-apiserver = %+v", api)
	}
	if len(api.Images) != 1 {
		t.Errorf("kube-apiserver images = %v", api.Images)
	}

	ing := byName["openshift-ingress"]
	if ing.Result != ComponentResultFail || ing.Failures != 1 {
		t.Errorf("openshift-ingress = %+v", ing)
	}
	if len(ing.FailureDetails) != 1 || ing.FailureDetails[0].Port != 443 {
		t.Errorf("openshift-ingress failureDetails = %+v", ing.FailureDetails)
	}

	unk := byName["unknown"]
	if unk.Result != ComponentResultSkip {
		t.Errorf("unknown = %+v", unk)
	}
}

func TestBuildTLSPostureAttestationObserveMode(t *testing.T) {
	t.Parallel()

	results := scanner.ScanResults{
		IPResults: []scanner.IPResult{{
			IP:                 "10.0.0.1",
			OpenshiftComponent: &k8s.OpenshiftComponent{Component: "foo"},
			PortResults: []scanner.PortResult{{
				Port:           443,
				Status:         scanner.StatusOK,
				TLS13Supported: false,
				MLKEMSupported: false,
			}},
		}},
	}

	doc := BuildTLSPostureAttestation(results, false, AttestationMeta{ScannerVersion: "dev"})
	if doc.Predicate.PolicyBar != PolicyBarObserve {
		t.Errorf("PolicyBar = %q, want observe", doc.Predicate.PolicyBar)
	}
	if doc.Predicate.Result != OverallResultPass {
		t.Errorf("observe mode Result = %q, want PASS", doc.Predicate.Result)
	}
	if doc.Predicate.Components[0].Result != ComponentResultPass {
		t.Errorf("component result = %q, want PASS in observe mode", doc.Predicate.Components[0].Result)
	}
}

func TestBuildTLSPostureAttestationTLSProfileBar(t *testing.T) {
	t.Parallel()

	results := scanner.ScanResults{
		TLSSecurityConfig: &k8s.TLSSecurityProfile{
			TLSAdherence: configv1.TLSAdherencePolicyStrictAllComponents,
		},
		IPResults: []scanner.IPResult{{
			IP:                 "10.0.0.1",
			OpenshiftComponent: &k8s.OpenshiftComponent{Component: "kube-apiserver"},
			PortResults: []scanner.PortResult{{
				Port:   6443,
				Status: scanner.StatusOK,
				APIServerTLSConfigCompliance: &scanner.TLSConfigComplianceResult{
					Version: false,
					Ciphers: true,
				},
			}},
		}},
	}

	doc := BuildTLSPostureAttestation(results, false, AttestationMeta{})
	if doc.Predicate.PolicyBar != PolicyBarTLSProfile {
		t.Errorf("PolicyBar = %q, want tls-profile", doc.Predicate.PolicyBar)
	}
	if doc.Predicate.Result != OverallResultFail {
		t.Errorf("Result = %q, want FAIL", doc.Predicate.Result)
	}
	if len(doc.Predicate.Components[0].FailureDetails) != 1 {
		t.Fatalf("expected failure detail, got %+v", doc.Predicate.Components[0].FailureDetails)
	}
}

func TestWriteAttestationFile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "tls-posture.intoto.json")
	results := scanner.ScanResults{
		Timestamp: "2026-07-23T12:00:00Z",
		IPResults: []scanner.IPResult{{
			IP:                 "10.0.0.1",
			OpenshiftComponent: &k8s.OpenshiftComponent{Component: "kube-apiserver"},
			PortResults: []scanner.PortResult{{
				Port:           6443,
				Status:         scanner.StatusOK,
				TLS13Supported: true,
				MLKEMSupported: true,
			}},
		}},
	}

	if err := WriteAttestationFile(results, path, true, AttestationMeta{ScannerVersion: "1.0"}); err != nil {
		t.Fatalf("WriteAttestationFile: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var doc TLSPostureAttestation
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if doc.Predicate.Result != OverallResultPass {
		t.Errorf("Result = %q", doc.Predicate.Result)
	}
	if FormatAttestationSummary(doc) == "" {
		t.Error("expected non-empty summary")
	}
}

func TestWriteOutputFilesAttestation(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	results := testScanResults()
	meta := &AttestationMeta{ScannerVersion: "test"}
	if err := WriteOutputFiles(results, dir, "", "", "", "attestation.json", false, meta); err != nil {
		t.Fatalf("WriteOutputFiles: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "attestation.json")); err != nil {
		t.Errorf("missing attestation file: %v", err)
	}
}
