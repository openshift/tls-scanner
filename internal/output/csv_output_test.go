package output

import (
	"encoding/csv"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/openshift/tls-scanner/internal/k8s"
	"github.com/openshift/tls-scanner/internal/scanner"
	"github.com/openshift/tls-scanner/internal/stringutil"
)

func TestWriteCSVOutput(t *testing.T) {
	t.Parallel()

	results := scanner.ScanResults{
		TLSSecurityConfig: &k8s.TLSSecurityProfile{
			IngressController: &k8s.IngressTLSProfile{
				Type:          "Intermediate",
				MinTLSVersion: "VersionTLS12",
				Ciphers:       []string{"TLS_AES_128_GCM_SHA256"},
			},
		},
		IPResults: []scanner.IPResult{{
			IP:     "10.0.0.1",
			Status: "scanned",
			Pod: &k8s.PodInfo{
				Name:      "pod-a",
				Namespace: "ns-a",
			},
			OpenshiftComponent: &k8s.OpenshiftComponent{
				Component:           "router",
				MaintainerComponent: "networking",
			},
			PortResults: []scanner.PortResult{{
				Port:                       443,
				Protocol:                   "tcp",
				Service:                    "https",
				ProcessName:                "nginx",
				TlsCiphers:                 []string{"TLS_AES_128_GCM_SHA256"},
				TlsVersions:                []string{"TLSv1.3"},
				TlsCertSignatureAlgorithms: []string{"SHA256 with RSA"},
				Status:                     scanner.StatusOK,
				Reason:                     "TLS scan successful",
				ListenAddress:              "0.0.0.0",
				TlsKeyExchange: &scanner.KeyExchangeInfo{
					Groups: []string{"x25519"},
					ForwardSecrecy: &scanner.ForwardSecrecy{
						KEMs: []string{"X25519MLKEM768"},
					},
				},
				TLS13Supported: true,
				MLKEMSupported: true,
				MLKEMCiphers:   []string{"X25519MLKEM768"},
				AllKEMs:        []string{"X25519MLKEM768"},
				IngressTLSConfigCompliance: &scanner.TLSConfigComplianceResult{
					Version: true,
					Ciphers: true,
				},
			}},
		}},
	}

	file := filepath.Join(t.TempDir(), "results.csv")
	if err := WriteCSVOutput(results, file); err != nil {
		t.Fatalf("WriteCSVOutput failed: %v", err)
	}

	f, err := os.Open(file)
	if err != nil {
		t.Fatalf("open csv file: %v", err)
	}
	defer f.Close()

	reader := csv.NewReader(f)
	rows, err := reader.ReadAll()
	if err != nil {
		t.Fatalf("read csv file: %v", err)
	}

	if len(rows) != 2 {
		t.Fatalf("expected header + 1 data row, got %d rows", len(rows))
	}
	if !reflect.DeepEqual(rows[0], csvColumns) {
		t.Fatalf("unexpected csv header: %#v", rows[0])
	}
	col := func(name string) string {
		for i, c := range csvColumns {
			if c == name {
				return rows[1][i]
			}
		}
		t.Fatalf("column %q not found in header", name)
		return ""
	}
	if col("IP") != "10.0.0.1" || col("Port") != "443" {
		t.Fatalf("unexpected ip/port values: %#v", rows[1][:2])
	}
	if col("TLS 1.3 Supported") != "Yes" || col("ML-KEM Supported") != "Yes" {
		t.Fatalf("unexpected yes/no formatting for TLS13/ML-KEM: %q %q", col("TLS 1.3 Supported"), col("ML-KEM Supported"))
	}
	if col("Cert Signature Algorithms") != "SHA256 with RSA" {
		t.Fatalf("unexpected cert signature algorithms value: %q", col("Cert Signature Algorithms"))
	}
}

func TestWriteScanErrorsCSV(t *testing.T) {
	t.Parallel()

	results := scanner.ScanResults{
		ScanErrors: []scanner.ScanError{
			{
				IP:        "10.0.0.9",
				Port:      6443,
				ErrorType: "timeout",
				ErrorMsg:  "deadline exceeded",
				PodName:   "api",
				Namespace: "openshift-kube-apiserver",
			},
		},
	}

	file := filepath.Join(t.TempDir(), "errors.csv")
	if err := WriteScanErrorsCSV(results, file); err != nil {
		t.Fatalf("WriteScanErrorsCSV failed: %v", err)
	}

	content, err := os.ReadFile(file)
	if err != nil {
		t.Fatalf("read file: %v", err)
	}

	text := string(content)
	if !strings.Contains(text, "Error Type") || !strings.Contains(text, "deadline exceeded") {
		t.Fatalf("unexpected scan errors csv content: %s", text)
	}
}

func TestCSVHelpers(t *testing.T) {
	t.Parallel()

	row := buildCSVRow([]string{"A", "B"}, map[string]string{"A": "1"})
	if !reflect.DeepEqual(row, []string{"1", "N/A"}) {
		t.Fatalf("unexpected buildCSVRow output: %#v", row)
	}

	if got := stringOrNA(""); got != "N/A" {
		t.Fatalf("expected N/A, got %q", got)
	}
	if got := joinOrNA(nil); got != "N/A" {
		t.Fatalf("expected N/A for empty slice, got %q", got)
	}
	if got := joinOrNA([]string{"a", "b"}); got != "a, b" {
		t.Fatalf("unexpected join result: %q", got)
	}
	if got := boolToYesNo(true); got != "Yes" {
		t.Fatalf("expected Yes, got %q", got)
	}
	if got := boolToYesNo(false); got != "No" {
		t.Fatalf("expected No, got %q", got)
	}

	dupes := stringutil.RemoveDuplicates([]string{"a", "a", "", "b"})
	if !reflect.DeepEqual(dupes, []string{"a", "b"}) {
		t.Fatalf("unexpected dedupe result: %#v", dupes)
	}
}
