package output

import (
	"encoding/xml"
	"os"
	"path/filepath"
	"strings"
	"testing"

	configv1 "github.com/openshift/api/config/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/openshift/tls-scanner/internal/k8s"
	"github.com/openshift/tls-scanner/internal/scanner"
)

func readJUnitSuite(t *testing.T, path string) JUnitTestSuite {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading JUnit output: %v", err)
	}
	var suite JUnitTestSuite
	if err := xml.Unmarshal(data, &suite); err != nil {
		t.Fatalf("invalid XML: %v", err)
	}
	return suite
}

func deploymentPodInfo(deployment, hash, suffix, namespace string) *k8s.PodInfo {
	isController := true
	name := deployment + "-" + hash + "-" + suffix
	return &k8s.PodInfo{
		Name:      name,
		Namespace: namespace,
		Pod: &v1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      name,
				Namespace: namespace,
				Labels:    map[string]string{"pod-template-hash": hash},
				OwnerReferences: []metav1.OwnerReference{{
					Kind:       "ReplicaSet",
					Name:       deployment + "-" + hash,
					Controller: &isController,
				}},
			},
		},
	}
}

func strictScanResults(ipResults ...scanner.IPResult) scanner.ScanResults {
	return scanner.ScanResults{
		TLSSecurityConfig: &k8s.TLSSecurityProfile{
			TLSAdherence: configv1.TLSAdherencePolicyStrictAllComponents,
			APIServer: &k8s.APIServerTLSProfile{
				Type:          "Modern",
				MinTLSVersion: "VersionTLS13",
			},
		},
		IPResults: ipResults,
	}
}

func TestWriteJUnitOutputBasic(t *testing.T) {
	t.Parallel()

	results := testScanResults()
	path := filepath.Join(t.TempDir(), "results.xml")

	if err := WriteJUnitOutput(results, path, false); err != nil {
		t.Fatalf("WriteJUnitOutput returned error: %v", err)
	}

	suite := readJUnitSuite(t, path)
	if suite.Name != "TLSSecurityScan" {
		t.Errorf("Name = %q, want %q", suite.Name, "TLSSecurityScan")
	}
	if suite.Tests != 1 {
		t.Errorf("Tests = %d, want 1", suite.Tests)
	}
	if suite.Failures != 0 {
		t.Errorf("Failures = %d, want 0", suite.Failures)
	}
}

func TestWriteJUnitOutputPQCFailures(t *testing.T) {
	t.Parallel()

	results := scanner.ScanResults{
		IPResults: []scanner.IPResult{{
			IP:     "10.0.0.1",
			Status: "scanned",
			Pod:    &k8s.PodInfo{Name: "pod-a", Namespace: "ns-a"},
			PortResults: []scanner.PortResult{{
				Port:           443,
				Protocol:       "tcp",
				Status:         scanner.StatusOK,
				TLS13Supported: false,
				MLKEMSupported: false,
			}},
		}},
	}

	path := filepath.Join(t.TempDir(), "pqc.xml")
	if err := WriteJUnitOutput(results, path, true); err != nil {
		t.Fatalf("WriteJUnitOutput returned error: %v", err)
	}

	suite := readJUnitSuite(t, path)
	if suite.Failures != 1 {
		t.Errorf("Failures = %d, want 1", suite.Failures)
	}
	if suite.TestCases[0].Failure == nil {
		t.Fatal("expected failure on PQC non-compliant port")
	}
	if strings.Contains(suite.TestCases[0].Name, tlsAdherenceGate) {
		t.Errorf("PQC test name %q must not carry the TLSAdherence gate tag", suite.TestCases[0].Name)
	}
}

func TestWriteJUnitOutputPQCPass(t *testing.T) {
	t.Parallel()

	results := scanner.ScanResults{
		IPResults: []scanner.IPResult{{
			IP:     "10.0.0.1",
			Status: "scanned",
			PortResults: []scanner.PortResult{{
				Port:           443,
				Protocol:       "tcp",
				Status:         scanner.StatusOK,
				TLS13Supported: true,
				MLKEMSupported: true,
			}},
		}},
	}

	path := filepath.Join(t.TempDir(), "pqc-pass.xml")
	if err := WriteJUnitOutput(results, path, true); err != nil {
		t.Fatalf("WriteJUnitOutput returned error: %v", err)
	}

	suite := readJUnitSuite(t, path)
	if suite.Failures != 0 {
		t.Errorf("Failures = %d, want 0", suite.Failures)
	}
}

func TestWriteJUnitOutputSkippableStatuses(t *testing.T) {
	t.Parallel()

	results := scanner.ScanResults{
		IPResults: []scanner.IPResult{{
			IP:     "10.0.0.1",
			Status: "scanned",
			PortResults: []scanner.PortResult{
				{Port: 1, Status: scanner.StatusNoPorts},
				{Port: 2, Status: scanner.StatusLocalhostOnly},
				{Port: 3, Status: scanner.StatusNoTLS},
				{Port: 4, Status: scanner.StatusProbePort},
			},
		}},
	}

	path := filepath.Join(t.TempDir(), "skip.xml")
	if err := WriteJUnitOutput(results, path, true); err != nil {
		t.Fatalf("WriteJUnitOutput returned error: %v", err)
	}

	suite := readJUnitSuite(t, path)
	if suite.Failures != 0 {
		t.Errorf("Failures = %d, want 0 for skippable statuses", suite.Failures)
	}
	// No-port, localhost-only, and probe-port entries have no external TLS
	// surface and emit no testcase; the NO_TLS port is reported as skipped.
	if suite.Tests != 1 {
		t.Errorf("Tests = %d, want 1", suite.Tests)
	}
	if suite.Skipped != 1 {
		t.Errorf("Skipped = %d, want 1", suite.Skipped)
	}
	if suite.TestCases[0].Skipped == nil {
		t.Error("expected NO_TLS endpoint to be reported as skipped")
	}
}

func TestWriteJUnitOutputTLSComplianceFailure(t *testing.T) {
	t.Parallel()

	results := strictScanResults(scanner.IPResult{
		IP:     "10.0.0.1",
		Status: "scanned",
		PortResults: []scanner.PortResult{{
			Port:     443,
			Protocol: "tcp",
			Status:   scanner.StatusOK,
			IngressTLSConfigCompliance: &scanner.TLSConfigComplianceResult{
				Version: false,
				Ciphers: true,
			},
		}},
	})

	path := filepath.Join(t.TempDir(), "compliance.xml")
	if err := WriteJUnitOutput(results, path, false); err != nil {
		t.Fatalf("WriteJUnitOutput returned error: %v", err)
	}

	suite := readJUnitSuite(t, path)
	if suite.Failures != 1 {
		t.Errorf("Failures = %d, want 1", suite.Failures)
	}
}

func TestWriteJUnitOutputStableNamesAcrossRuns(t *testing.T) {
	t.Parallel()

	// The same deployment endpoint observed in two runs with different pod
	// hashes, pod suffixes, and IPs must produce identical test names.
	runs := []scanner.IPResult{
		{
			IP:     "10.128.2.14",
			Status: "scanned",
			Pod:    deploymentPodInfo("networking-console-plugin", "544b86b7cd", "qp9lp", "openshift-network-console"),
			PortResults: []scanner.PortResult{{
				Port:   9443,
				Status: scanner.StatusOK,
				APIServerTLSConfigCompliance: &scanner.TLSConfigComplianceResult{
					Version: true,
					Ciphers: false,
				},
			}},
		},
		{
			IP:     "10.131.0.6",
			Status: "scanned",
			Pod:    deploymentPodInfo("networking-console-plugin", "54fdc79fd7", "r2rk6", "openshift-network-console"),
			PortResults: []scanner.PortResult{{
				Port:   9443,
				Status: scanner.StatusOK,
				APIServerTLSConfigCompliance: &scanner.TLSConfigComplianceResult{
					Version: true,
					Ciphers: false,
				},
			}},
		},
	}

	var names []string
	for i, ipResult := range runs {
		path := filepath.Join(t.TempDir(), "run.xml")
		if err := WriteJUnitOutput(strictScanResults(ipResult), path, false); err != nil {
			t.Fatalf("WriteJUnitOutput run %d returned error: %v", i, err)
		}
		suite := readJUnitSuite(t, path)
		if suite.Tests != 1 {
			t.Fatalf("run %d: Tests = %d, want 1", i, suite.Tests)
		}
		names = append(names, suite.TestCases[0].Name)
	}

	if names[0] != names[1] {
		t.Errorf("test names differ across runs:\n  %q\n  %q", names[0], names[1])
	}
	want := "[sig-security][OCPFeatureGate:TLSAdherence] ns/openshift-network-console deployment/networking-console-plugin port/9443 should comply with the cluster TLS profile"
	if names[0] != want {
		t.Errorf("test name = %q, want %q", names[0], want)
	}
}

func TestWriteJUnitOutputAggregatesReplicas(t *testing.T) {
	t.Parallel()

	// One replica scanned clean, one failing, one unreachable: a single
	// testcase is emitted for the workload and it fails.
	results := strictScanResults(
		scanner.IPResult{
			IP:     "10.128.2.14",
			Status: "scanned",
			Pod:    deploymentPodInfo("router-default", "ddc8bbfc7", "mrf94", "openshift-ingress"),
			PortResults: []scanner.PortResult{{
				Port:   8443,
				Status: scanner.StatusOK,
				APIServerTLSConfigCompliance: &scanner.TLSConfigComplianceResult{
					Version: true,
					Ciphers: true,
				},
			}},
		},
		scanner.IPResult{
			IP:     "10.131.0.6",
			Status: "scanned",
			Pod:    deploymentPodInfo("router-default", "ddc8bbfc7", "dv9wb", "openshift-ingress"),
			PortResults: []scanner.PortResult{{
				Port:   8443,
				Status: scanner.StatusOK,
				APIServerTLSConfigCompliance: &scanner.TLSConfigComplianceResult{
					Version: false,
					Ciphers: false,
				},
			}},
		},
		scanner.IPResult{
			IP:     "10.129.2.7",
			Status: "scanned",
			Pod:    deploymentPodInfo("router-default", "ddc8bbfc7", "zz9zz", "openshift-ingress"),
			PortResults: []scanner.PortResult{{
				Port:   8443,
				Status: scanner.StatusNoTLS,
				Reason: "Port open but no TLS detected",
			}},
		},
	)

	path := filepath.Join(t.TempDir(), "aggregate.xml")
	if err := WriteJUnitOutput(results, path, false); err != nil {
		t.Fatalf("WriteJUnitOutput returned error: %v", err)
	}

	suite := readJUnitSuite(t, path)
	if suite.Tests != 1 {
		t.Fatalf("Tests = %d, want 1 aggregated testcase, got names: %v", suite.Tests, suite.TestCases)
	}
	if suite.Failures != 1 {
		t.Errorf("Failures = %d, want 1", suite.Failures)
	}
	failure := suite.TestCases[0].Failure
	if failure == nil {
		t.Fatal("expected aggregated testcase to fail when any replica fails")
	}
	if !strings.Contains(failure.Content, "router-default-ddc8bbfc7-dv9wb") {
		t.Errorf("failure content should identify the failing pod, got: %q", failure.Content)
	}
}

func TestWriteJUnitOutputSkipsUnreachableWorkload(t *testing.T) {
	t.Parallel()

	// Every replica unreachable for a TLS handshake (e.g. NetworkPolicy
	// blocks the scanner): the testcase must be skipped, not passed.
	results := strictScanResults(scanner.IPResult{
		IP:     "10.129.2.7",
		Status: "scanned",
		Pod:    deploymentPodInfo("networking-console-plugin", "54fdc79fd7", "vvs2b", "openshift-network-console"),
		PortResults: []scanner.PortResult{{
			Port:   9443,
			Status: scanner.StatusNoTLS,
			Reason: "Port open but no TLS detected",
		}},
	})

	path := filepath.Join(t.TempDir(), "unreachable.xml")
	if err := WriteJUnitOutput(results, path, false); err != nil {
		t.Fatalf("WriteJUnitOutput returned error: %v", err)
	}

	suite := readJUnitSuite(t, path)
	if suite.Tests != 1 || suite.Skipped != 1 || suite.Failures != 0 {
		t.Fatalf("Tests/Skipped/Failures = %d/%d/%d, want 1/1/0", suite.Tests, suite.Skipped, suite.Failures)
	}
	if suite.TestCases[0].Skipped == nil {
		t.Fatal("expected skipped element on unreachable workload")
	}
	if !strings.Contains(suite.TestCases[0].Skipped.Message, "no TLS detected") {
		t.Errorf("skip message should carry the reason, got %q", suite.TestCases[0].Skipped.Message)
	}
}

func TestWriteJUnitOutputGateTagOnlyWhenEnforced(t *testing.T) {
	t.Parallel()

	ipResult := scanner.IPResult{
		IP:     "10.0.0.1",
		Status: "scanned",
		Pod:    deploymentPodInfo("console", "754974bc6f", "dml4t", "openshift-console"),
		PortResults: []scanner.PortResult{{
			Port:   8443,
			Status: scanner.StatusOK,
		}},
	}

	enforced := strictScanResults(ipResult)
	notEnforced := scanner.ScanResults{IPResults: []scanner.IPResult{ipResult}}

	enforcedPath := filepath.Join(t.TempDir(), "enforced.xml")
	if err := WriteJUnitOutput(enforced, enforcedPath, false); err != nil {
		t.Fatalf("WriteJUnitOutput returned error: %v", err)
	}
	notEnforcedPath := filepath.Join(t.TempDir(), "not-enforced.xml")
	if err := WriteJUnitOutput(notEnforced, notEnforcedPath, false); err != nil {
		t.Fatalf("WriteJUnitOutput returned error: %v", err)
	}

	enforcedName := readJUnitSuite(t, enforcedPath).TestCases[0].Name
	notEnforcedName := readJUnitSuite(t, notEnforcedPath).TestCases[0].Name

	if !strings.Contains(enforcedName, tlsAdherenceGate) {
		t.Errorf("enforced test name %q should contain %q", enforcedName, tlsAdherenceGate)
	}
	if strings.Contains(notEnforcedName, tlsAdherenceGate) {
		t.Errorf("non-enforced test name %q must not contain %q", notEnforcedName, tlsAdherenceGate)
	}
}

func TestWriteJUnitOutputCreatesDirectory(t *testing.T) {
	t.Parallel()

	results := testScanResults()
	path := filepath.Join(t.TempDir(), "deep", "nested", "results.xml")

	if err := WriteJUnitOutput(results, path, false); err != nil {
		t.Fatalf("WriteJUnitOutput returned error: %v", err)
	}

	if _, err := os.Stat(path); err != nil {
		t.Errorf("expected file at %s: %v", path, err)
	}
}

func TestWriteJUnitOutputUsesClassNameFromPod(t *testing.T) {
	t.Parallel()

	results := testScanResults()
	path := filepath.Join(t.TempDir(), "classname.xml")

	if err := WriteJUnitOutput(results, path, false); err != nil {
		t.Fatalf("WriteJUnitOutput returned error: %v", err)
	}

	suite := readJUnitSuite(t, path)
	if suite.TestCases[0].ClassName != "ns-a/pod/pod-a" {
		t.Errorf("ClassName = %q, want %q", suite.TestCases[0].ClassName, "ns-a/pod/pod-a")
	}
}

func TestWriteJUnitOutputUsesClassNameFromIP(t *testing.T) {
	t.Parallel()

	results := scanner.ScanResults{
		IPResults: []scanner.IPResult{{
			IP:     "10.0.0.1",
			Status: "scanned",
			PortResults: []scanner.PortResult{{
				Port: 443, Protocol: "tcp", Status: scanner.StatusOK,
			}},
		}},
	}

	path := filepath.Join(t.TempDir(), "classname-ip.xml")
	if err := WriteJUnitOutput(results, path, false); err != nil {
		t.Fatalf("WriteJUnitOutput returned error: %v", err)
	}

	suite := readJUnitSuite(t, path)
	if suite.TestCases[0].ClassName != "10.0.0.1" {
		t.Errorf("ClassName = %q, want %q (from IP)", suite.TestCases[0].ClassName, "10.0.0.1")
	}
}
