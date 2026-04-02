package output

import (
	"fmt"
	"os"
	"testing"

	"github.com/openshift/tls-scanner/internal/scanner"
)

func buildLargeResults(n int) scanner.ScanResults {
	results := scanner.ScanResults{
		Timestamp:  "2025-01-15T00:00:00Z",
		TotalIPs:   n,
		ScannedIPs: n,
		IPResults:  make([]scanner.IPResult, 0, n),
	}

	for i := 0; i < n; i++ {
		ip := fmt.Sprintf("10.128.%d.%d", i/256, i%256)
		port := 8443 + (i % 10)
		pr := scanner.PortResult{
			Port:     port,
			Protocol: "tcp",
			State:    "open",
			Service:  "ssl/tls",
			Status:   scanner.StatusOK,
			Reason:   "TLS scan successful",
			TlsVersions: []string{"TLSv1.2", "TLSv1.3"},
			TlsCiphers: []string{
				"ECDHE-RSA-AES128-GCM-SHA256",
				"ECDHE-RSA-AES256-GCM-SHA384",
				"ECDHE-ECDSA-AES128-GCM-SHA256",
				"TLS_AES_128_GCM_SHA256",
				"TLS_AES_256_GCM_SHA384",
				"TLS_CHACHA20_POLY1305_SHA256",
			},
			TlsKeyExchange: &scanner.KeyExchangeInfo{
				Groups: []string{"x25519", "secp256r1", "secp384r1"},
				ForwardSecrecy: &scanner.ForwardSecrecy{
					Supported: true,
					ECDHE:     []string{"ECDHE-RSA-AES128-GCM-SHA256"},
					KEMs:      []string{"x25519"},
				},
			},
		}

		results.IPResults = append(results.IPResults, scanner.IPResult{
			IP:          ip,
			Status:      "scanned",
			OpenPorts:   []int{port},
			PortResults: []scanner.PortResult{pr},
		})
	}

	return results
}

func BenchmarkWriteCSVOutput(b *testing.B) {
	results := buildLargeResults(200)
	tmpFile, _ := os.CreateTemp("", "bench-csv-*.csv")
	tmpName := tmpFile.Name()
	tmpFile.Close()
	defer os.Remove(tmpName)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = WriteCSVOutput(results, tmpName)
	}
}

func BenchmarkWriteJUnitOutput(b *testing.B) {
	results := buildLargeResults(200)
	tmpFile, _ := os.CreateTemp("", "bench-junit-*.xml")
	tmpName := tmpFile.Name()
	tmpFile.Close()
	defer os.Remove(tmpName)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = WriteJUnitOutput(results, tmpName, false)
	}
}
