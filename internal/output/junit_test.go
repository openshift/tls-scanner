package output

import (
	"encoding/xml"
	"os"
	"path/filepath"
	"testing"

	configv1 "github.com/openshift/api/config/v1"

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
	if suite.Timestamp != "2026-05-13T12:00:00Z" {
		t.Errorf("Timestamp = %q, want %q", suite.Timestamp, "2026-05-13T12:00:00Z")
	}
	if suite.Hostname == "" {
		t.Error("Hostname should not be empty")
	}
	if suite.Time != 5.0 {
		t.Errorf("Time = %f, want 5.0", suite.Time)
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
				{Port: 1, Status: scanner.StatusNoPorts, TLS13Supported: false, MLKEMSupported: false},
				{Port: 2, Status: scanner.StatusLocalhostOnly, TLS13Supported: false, MLKEMSupported: false},
				{Port: 3, Status: scanner.StatusNoTLS, TLS13Supported: false, MLKEMSupported: false},
				{Port: 4, Status: scanner.StatusProbePort, TLS13Supported: false, MLKEMSupported: false},
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
	if suite.Tests != 4 {
		t.Errorf("Tests = %d, want 4", suite.Tests)
	}
}

func TestWriteJUnitOutputTLSComplianceFailure(t *testing.T) {
	t.Parallel()

	results := scanner.ScanResults{
		TLSSecurityConfig: &k8s.TLSSecurityProfile{
			TLSAdherence: configv1.TLSAdherencePolicyStrictAllComponents,
			APIServer: &k8s.APIServerTLSProfile{
				Type:          "Intermediate",
				MinTLSVersion: "VersionTLS12",
				Ciphers:       []string{"TLS_AES_128_GCM_SHA256"},
			},
		},
		IPResults: []scanner.IPResult{{
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
		}},
	}

	path := filepath.Join(t.TempDir(), "compliance.xml")
	if err := WriteJUnitOutput(results, path, false); err != nil {
		t.Fatalf("WriteJUnitOutput returned error: %v", err)
	}

	suite := readJUnitSuite(t, path)
	if suite.Failures != 1 {
		t.Errorf("Failures = %d, want 1", suite.Failures)
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
	if suite.TestCases[0].ClassName != "pod-a" {
		t.Errorf("ClassName = %q, want %q (from pod name)", suite.TestCases[0].ClassName, "pod-a")
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
