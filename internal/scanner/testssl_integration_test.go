package scanner

import (
	"os/exec"
	"testing"
	"time"
)

var integrationTargets = []struct {
	ip   string
	port int
	desc string
}{
	{"1.1.1.1", 443, "Cloudflare DNS"},
	{"8.8.8.8", 443, "Google DNS"},
	{"9.9.9.9", 443, "Quad9 DNS"},
}

func skipIfNoTestSSL(t *testing.T) {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	if _, err := exec.LookPath("testssl.sh"); err != nil {
		t.Skip("testssl.sh not installed")
	}
}

func TestIntegrationSingleTarget(t *testing.T) {
	skipIfNoTestSSL(t)

	tgt := integrationTargets[0]
	jobs := []ScanJob{{IP: tgt.ip, Port: tgt.port}}

	start := time.Now()
	results := batchScan(jobs, 1, nil, nil, testPolicy(t))
	elapsed := time.Since(start)

	t.Logf("Single target %s (%s:%d): %v", tgt.desc, tgt.ip, tgt.port, elapsed)

	if len(results) == 0 {
		t.Fatal("expected results, got none")
	}

	r := results[0]
	t.Logf("  status=%s versions=%v ciphers=%d", r.result.Status, r.result.TlsVersions, len(r.result.TlsCiphers))
	if r.result.TlsKeyExchange != nil {
		t.Logf("  groups=%v KEMs=%v", r.result.TlsKeyExchange.Groups, r.result.TlsKeyExchange.ForwardSecrecy.KEMs)
	}
	t.Logf("  PQC: tls13=%v mlkem=%v mlkemCiphers=%v allKEMs=%v",
		r.result.TLS13Supported, r.result.MLKEMSupported, r.result.MLKEMCiphers, r.result.AllKEMs)

	if r.result.Status != StatusOK {
		t.Errorf("expected status OK, got %s: %s", r.result.Status, r.result.Reason)
	}
	if len(r.result.TlsVersions) == 0 {
		t.Error("expected at least one TLS version")
	}
	if !r.result.TLS13Supported {
		t.Error("expected TLS13Supported=true (Cloudflare supports TLS 1.3)")
	}
	if !r.result.MLKEMSupported {
		t.Error("expected MLKEMSupported=true (Cloudflare supports ML-KEM)")
	}
}

func TestIntegrationBatchTargets(t *testing.T) {
	skipIfNoTestSSL(t)

	jobs := make([]ScanJob, len(integrationTargets))
	for i, tgt := range integrationTargets {
		jobs[i] = ScanJob{IP: tgt.ip, Port: tgt.port}
	}

	start := time.Now()
	results := batchScan(jobs, 4, nil, nil, testPolicy(t))
	elapsed := time.Since(start)

	t.Logf("Batch %d targets (MAX_PARALLEL=4): %v (%.1fs/target)",
		len(jobs), elapsed, elapsed.Seconds()/float64(len(jobs)))

	if len(results) != len(jobs) {
		t.Fatalf("expected %d results, got %d", len(jobs), len(results))
	}

	for _, r := range results {
		t.Logf("  %s:%d status=%s versions=%v ciphers=%d",
			r.ip, r.result.Port, r.result.Status, r.result.TlsVersions, len(r.result.TlsCiphers))
		if r.result.Status != StatusOK {
			t.Errorf("  %s:%d expected OK, got %s", r.ip, r.result.Port, r.result.Status)
		}
	}
}

func TestIntegrationParallelScaling(t *testing.T) {
	skipIfNoTestSSL(t)

	jobs := make([]ScanJob, len(integrationTargets))
	for i, tgt := range integrationTargets {
		jobs[i] = ScanJob{IP: tgt.ip, Port: tgt.port}
	}

	t.Log("--- Sequential run (MAX_PARALLEL=1) ---")
	start := time.Now()
	seqResults := batchScan(jobs, 1, nil, nil, testPolicy(t))
	sequential := time.Since(start)

	t.Log("--- Parallel run (MAX_PARALLEL=", len(jobs), ") ---")
	start = time.Now()
	parResults := batchScan(jobs, len(jobs), nil, nil, testPolicy(t))
	parallel := time.Since(start)

	speedup := sequential.Seconds() / parallel.Seconds()

	t.Logf("\n=== TESTSSL SCALING RESULTS ===")
	t.Logf("Targets:    %d", len(jobs))
	t.Logf("Sequential: %v (%.1fs/target)", sequential, sequential.Seconds()/float64(len(jobs)))
	t.Logf("Parallel:   %v (%.1fs/target)", parallel, parallel.Seconds()/float64(len(jobs)))
	t.Logf("Speedup:    %.2fx", speedup)

	for i, tgt := range integrationTargets {
		seqStatus, parStatus := "missing", "missing"
		if i < len(seqResults) {
			seqStatus = string(seqResults[i].result.Status)
		}
		if i < len(parResults) {
			parStatus = string(parResults[i].result.Status)
		}
		t.Logf("  %s: seq=%s par=%s", tgt.desc, seqStatus, parStatus)
	}
}
