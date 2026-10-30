package output

import (
	"io"
	"os"
	"strings"
	"testing"

	"github.com/openshift/tls-scanner/internal/k8s"
	"github.com/openshift/tls-scanner/internal/scanner"
)

// captureStdout runs fn and returns everything written to os.Stdout.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("creating pipe: %v", err)
	}

	orig := os.Stdout
	os.Stdout = w
	defer func() { os.Stdout = orig }()

	fn()

	if err := w.Close(); err != nil {
		t.Fatalf("closing pipe writer: %v", err)
	}
	os.Stdout = orig

	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("reading pipe: %v", err)
	}
	if err := r.Close(); err != nil {
		t.Fatalf("closing pipe reader: %v", err)
	}

	return string(out)
}

func TestPrintPQCClusterResultsSkipsUnscannablePorts(t *testing.T) {
	results := scanner.ScanResults{
		Timestamp:  "2026-01-01T00:00:00Z",
		TotalIPs:   2,
		ScannedIPs: 2,
		IPResults: []scanner.IPResult{
			{
				IP:                 "10.0.0.1",
				Pod:                &k8s.PodInfo{Namespace: "openshift-kube-apiserver", Name: "kube-apiserver-abc"},
				OpenshiftComponent: &k8s.OpenshiftComponent{Component: "kube-apiserver"},
				PortResults: []scanner.PortResult{
					{Port: 8443, Status: scanner.StatusOK, TLS13Supported: true, MLKEMSupported: true},
					{Port: 8080, Status: scanner.StatusNoTLS, Reason: "Port open but no TLS detected"},
					{Port: 9000, Status: scanner.StatusLocalhostOnly, Reason: "Listening on localhost only"},
				},
			},
			{
				IP: "10.0.0.2",
				PortResults: []scanner.PortResult{
					{Port: 443, Status: scanner.StatusOK, TLS13Supported: true},
					{Port: 9091, Status: scanner.StatusProbePort, Reason: "Health probe endpoint"},
					{Port: 0, Status: scanner.StatusNoPorts},
				},
			},
		},
	}

	out := captureStdout(t, func() { PrintPQCClusterResults(results) })

	if strings.Contains(out, "Port 9000:\n") || strings.Contains(out, "Port 9091:\n") {
		t.Errorf("skipped ports must not be rendered as probed ports:\n%s", out)
	}

	for _, want := range []string{
		"Pod: openshift-kube-apiserver/kube-apiserver-abc\n",
		"Component: kube-apiserver\n",
		"Port 8080: skipped (NO_TLS): Port open but no TLS detected",
		"Port 9000: skipped (LOCALHOST_ONLY): Listening on localhost only",
		"Port 9091: skipped (PROBE_PORT): Health probe endpoint",
		"No TCP ports declared",
		// Probed ports: 8443 and 443. Skipped: 8080, 9000, 9091, and the no-ports entry.
		"Total Ports Scanned: 2\n",
		"Ports Skipped:       4\n",
		"TLS 1.3 Ready:       2\n",
		"ML-KEM Ready:        1\n",
		"Fully PQC Ready:     1 (50% of scanned ports)\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}

	// Statuses are ordered deterministically in the breakdown.
	if strings.Index(out, "LOCALHOST_ONLY:") > strings.Index(out, "PROBE_PORT:") {
		t.Errorf("skip breakdown is not sorted:\n%s", out)
	}
}

func TestPrintPQCClusterResultsNoScannedPorts(t *testing.T) {
	results := scanner.ScanResults{
		IPResults: []scanner.IPResult{
			{IP: "10.0.0.1", PortResults: []scanner.PortResult{{Status: scanner.StatusNoPorts}}},
		},
	}

	out := captureStdout(t, func() { PrintPQCClusterResults(results) })

	for _, want := range []string{
		"Total Ports Scanned: 0\n",
		"Fully PQC Ready:     0\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "% of scanned ports") {
		t.Errorf("percentage must be omitted when no ports were scanned:\n%s", out)
	}
}

// A port that was probed and offers only TLS 1.2 is a real PQC failure: it
// must render NOT SUPPORTED (unlike skipped ports) and must not count as ready.
func TestPrintPQCClusterResultsNotSupportedPort(t *testing.T) {
	results := scanner.ScanResults{
		IPResults: []scanner.IPResult{
			{
				IP: "10.0.0.3",
				PortResults: []scanner.PortResult{
					{
						Port:           8443,
						Status:         scanner.StatusOK,
						TLS13Supported: false,
						MLKEMSupported: false,
						TlsVersions:    []string{"TLSv1.2"},
						AllKEMs:        []string{"SecP256r1MLKEM768"},
					},
					{Port: 9100, Status: scanner.StatusProbePort}, // skipped, no reason
				},
			},
		},
	}

	out := captureStdout(t, func() { PrintPQCClusterResults(results) })

	for _, want := range []string{
		"Port 8443:\n",
		"TLS 1.3:  NOT SUPPORTED\n",
		"ML-KEM:   NOT SUPPORTED\n",
		"TLS Versions: TLSv1.2\n",
		"All KEMs: SecP256r1MLKEM768\n",
		"Port 9100: skipped (PROBE_PORT)\n",
		"Total Ports Scanned: 1\n",
		"TLS 1.3 Ready:       0\n",
		"Fully PQC Ready:     0 (0% of scanned ports)\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
}

func TestPrintPQCClusterResultsIPError(t *testing.T) {
	results := scanner.ScanResults{
		IPResults: []scanner.IPResult{
			{
				IP:          "10.0.0.4",
				Error:       "connection refused",
				PortResults: []scanner.PortResult{{Port: 6443, Status: scanner.StatusOK, TLS13Supported: true}},
			},
		},
	}

	out := captureStdout(t, func() { PrintPQCClusterResults(results) })

	if !strings.Contains(out, "  Error: connection refused\n") {
		t.Errorf("output missing IP error line:\n%s", out)
	}
	// An IP that failed discovery has no probed ports to render.
	if strings.Contains(out, "Port 6443") {
		t.Errorf("ports must not be rendered for an IP with an error:\n%s", out)
	}
}
