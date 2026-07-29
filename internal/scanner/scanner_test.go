package scanner

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/openshift/tls-scanner/internal/k8s"
	"github.com/openshift/tls-scanner/internal/testutil"
)

func makePod(name, namespace, ip string, ports ...int32) k8s.PodInfo {
	var containerPorts []v1.ContainerPort
	for _, p := range ports {
		containerPorts = append(containerPorts, v1.ContainerPort{ContainerPort: p, Protocol: v1.ProtocolTCP})
	}
	pod := &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec: v1.PodSpec{
			Containers: []v1.Container{{Name: "main", Ports: containerPorts}},
		},
	}
	return k8s.PodInfo{
		Name: name, Namespace: namespace, IPs: []string{ip},
		Containers: []string{"main"}, Pod: pod,
	}
}

func TestBatchScanStarttlsRouting(t *testing.T) {
	testutil.InstallMockTestSSL(t)

	jobs := []ScanJob{
		{IP: "10.0.0.1", Port: 443},
		{IP: "10.0.0.2", Port: 5432},
		{IP: "10.0.0.3", Port: 8443},
		{IP: "10.0.0.4", Port: 3306},
	}
	starttlsPorts := StarttlsPorts{5432: "postgres", 3306: "mysql"}

	results := batchScan(jobs, 4, nil, nil, testPolicy(t), DefaultScanTimeouts, starttlsPorts)

	if len(results) != 4 {
		t.Fatalf("expected 4 results, got %d", len(results))
	}

	resultByIP := map[string]portScanResult{}
	for _, r := range results {
		resultByIP[r.ip] = r
	}

	for _, tc := range []struct {
		ip            string
		wantSTARTTLS  string
		wantPort      int
	}{
		{"10.0.0.1", "", 443},
		{"10.0.0.2", "postgres", 5432},
		{"10.0.0.3", "", 8443},
		{"10.0.0.4", "mysql", 3306},
	} {
		r, ok := resultByIP[tc.ip]
		if !ok {
			t.Errorf("missing result for %s", tc.ip)
			continue
		}
		if r.result.STARTTLSProtocol != tc.wantSTARTTLS {
			t.Errorf("%s: STARTTLSProtocol = %q, want %q", tc.ip, r.result.STARTTLSProtocol, tc.wantSTARTTLS)
		}
		if r.result.Port != tc.wantPort {
			t.Errorf("%s: Port = %d, want %d", tc.ip, r.result.Port, tc.wantPort)
		}
		if r.result.Status != StatusOK {
			t.Errorf("%s: Status = %s, want OK", tc.ip, r.result.Status)
		}
	}
}

func TestScanWithMockTestSSL(t *testing.T) {
	testutil.InstallMockTestSSL(t)

	jobs := []ScanJob{
		{IP: "10.0.0.1", Port: 443},
		{IP: "10.0.0.2", Port: 8443},
	}
	results := Scan(jobs, 2, nil, nil, testPolicy(t), DefaultScanTimeouts, nil)

	if results.ScannedIPs != 2 {
		t.Fatalf("expected 2 scanned IPs, got %d", results.ScannedIPs)
	}

	for _, ir := range results.IPResults {
		if len(ir.PortResults) == 0 {
			t.Fatalf("IP %s: no port results", ir.IP)
		}
		pr := ir.PortResults[0]
		if pr.Status != StatusOK {
			t.Errorf("IP %s: expected OK, got %s (%s)", ir.IP, pr.Status, pr.Reason)
		}
		if len(pr.TlsVersions) == 0 {
			t.Errorf("IP %s: expected TLS versions", ir.IP)
		}
	}
}

func TestScanPQCEnrichment(t *testing.T) {
	testutil.InstallMockTestSSL(t)

	jobs := []ScanJob{{IP: "10.0.0.1", Port: 443}}
	results := Scan(jobs, 1, nil, nil, testPolicy(t), DefaultScanTimeouts, nil)

	pr := results.IPResults[0].PortResults[0]

	if !pr.TLS13Supported {
		t.Error("expected TLS13Supported=true")
	}
	if !pr.MLKEMSupported {
		t.Error("expected MLKEMSupported=true")
	}
	if len(pr.MLKEMCiphers) == 0 {
		t.Error("expected MLKEMCiphers populated")
	}
	found := false
	for _, k := range pr.MLKEMCiphers {
		if k == "x25519mlkem768" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected x25519mlkem768 in MLKEMCiphers, got %v", pr.MLKEMCiphers)
	}
}

func TestPerformClusterScanWithMockPods(t *testing.T) {
	testutil.InstallMockTestSSL(t)

	pods := []k8s.PodInfo{
		makePod("apiserver-1", "openshift-apiserver", "10.128.0.10", 8443),
		makePod("etcd-1", "openshift-etcd", "10.128.0.20", 2379, 2380),
		makePod("no-ports", "openshift-console", "10.128.0.30"),
	}

	results := PerformClusterScan(pods, 2, nil, testPolicy(t), DefaultScanTimeouts, nil, nil)

	if results.ScannedIPs != 3 {
		t.Errorf("expected 3 scanned IPs (including no-ports), got %d", results.ScannedIPs)
	}

	portsByIP := map[string][]PortResult{}
	for _, ir := range results.IPResults {
		portsByIP[ir.IP] = ir.PortResults
	}

	if prs, ok := portsByIP["10.128.0.10"]; ok {
		if len(prs) != 1 || prs[0].Port != 8443 {
			t.Errorf("apiserver: expected port 8443, got %v", prs)
		}
		if prs[0].Status != StatusOK {
			t.Errorf("apiserver: expected OK, got %s", prs[0].Status)
		}
	} else {
		t.Error("missing results for apiserver 10.128.0.10")
	}

	if prs, ok := portsByIP["10.128.0.20"]; ok {
		if len(prs) != 2 {
			t.Errorf("etcd: expected 2 port results, got %d", len(prs))
		}
	} else {
		t.Error("missing results for etcd 10.128.0.20")
	}

	if prs, ok := portsByIP["10.128.0.30"]; ok {
		if len(prs) != 1 || prs[0].Status != StatusNoPorts {
			t.Errorf("no-ports pod: expected StatusNoPorts, got %v", prs)
		}
	} else {
		t.Error("missing results for no-ports pod 10.128.0.30")
	}
}

func TestAssembleResults(t *testing.T) {
	batch1 := []portScanResult{
		{ip: "10.0.0.1", result: PortResult{Port: 443, Status: StatusOK}},
		{ip: "10.0.0.1", result: PortResult{Port: 8443, Status: StatusOK}},
	}
	batch2 := []portScanResult{
		{ip: "10.0.0.2", result: PortResult{Port: 443, Status: StatusNoTLS}},
	}

	results := assembleResults(time.Now(), 0, nil, batch1, batch2)

	if results.ScannedIPs != 2 {
		t.Errorf("expected 2 scanned IPs, got %d", results.ScannedIPs)
	}

	portsByIP := map[string]int{}
	for _, ir := range results.IPResults {
		portsByIP[ir.IP] = len(ir.PortResults)
	}
	if portsByIP["10.0.0.1"] != 2 {
		t.Errorf("expected 2 port results for 10.0.0.1, got %d", portsByIP["10.0.0.1"])
	}
	if portsByIP["10.0.0.2"] != 1 {
		t.Errorf("expected 1 port result for 10.0.0.2, got %d", portsByIP["10.0.0.2"])
	}
}

func TestAssembleResultsWithSharedHostNetwork(t *testing.T) {
	podDefinitions := []struct {
		name      string
		namespace string
		ip        string
		port      int32
	}{
		// Pods sharing IPv4 address
		{"node-exporter", "openshift-monitoring", "10.0.1.100", 9100},
		{"kube-proxy", "openshift-network", "10.0.1.100", 10256},
		{"crio", "openshift-node", "10.0.1.100", 9537},
		// Pods sharing IPv6 address
		{"kubelet", "openshift-node", "2001:db8::1", 10250},
		{"ovn-controller", "openshift-ovn-kubernetes", "2001:db8::1", 29102},
	}

	var batch []portScanResult
	for _, def := range podDefinitions {
		pod := makePod(def.name, def.namespace, def.ip, def.port)
		batch = append(batch, portScanResult{
			ip:     def.ip,
			pod:    pod,
			result: PortResult{Port: int(def.port), Status: StatusOK},
		})
	}

	expectedPods := make(map[string]struct {
		ip   string
		port int
	})
	for _, def := range podDefinitions {
		expectedPods[def.namespace+"/"+def.name] = struct {
			ip   string
			port int
		}{def.ip, int(def.port)}
	}

	results := assembleResults(time.Now(), 0, nil, batch)

	// ScannedIPs should count unique IPs (2: one IPv4, one IPv6)
	if results.ScannedIPs != 2 {
		t.Errorf("expected 2 unique scanned IPs, got %d", results.ScannedIPs)
	}

	// IPResults should have separate entries for each pod
	if len(results.IPResults) != len(podDefinitions) {
		t.Errorf("expected %d IPResults (one per pod), got %d", len(podDefinitions), len(results.IPResults))
	}

	for _, ir := range results.IPResults {
		if ir.Pod == nil {
			t.Errorf("unable to find Pod entry for %#v entry", ir)
			continue
		}
		key := ir.Pod.Namespace + "/" + ir.Pod.Name
		expected, ok := expectedPods[key]
		if !ok {
			t.Errorf("unexpected IPResult for pod %s", key)
			continue
		}
		if ir.IP != expected.ip {
			t.Errorf("%s: expected IP %s, got %s", ir.Pod.Name, expected.ip, ir.IP)
		}
		if len(ir.PortResults) != 1 || ir.PortResults[0].Port != expected.port {
			t.Errorf("%s: expected port %d, got %v", ir.Pod.Name, expected.port, ir.PortResults)
		}
		delete(expectedPods, key)
	}

	for key := range expectedPods {
		t.Errorf("missing IPResult for pod %s", key)
	}
}

func TestDeduplicateScanJobs(t *testing.T) {
	const (
		sharedIP = "10.0.1.100"
		port     = 9100
	)

	// Pod that declares the port in its spec
	podWithSpec := makePod("node-exporter", "openshift-monitoring", sharedIP, port)

	// Pod that doesn't declare the port (discovered via /proc)
	podWithoutSpec := makePod("hostnetwork-pod", "openshift-node", sharedIP)

	// Another pod that also declares the port
	podAlsoWithSpec := makePod("another-exporter", "openshift-monitoring", sharedIP, port)

	tests := []struct {
		name     string
		jobs     []ScanJob
		expected int
		wantPod  string
	}{
		{
			name: "no duplicates",
			jobs: []ScanJob{
				{IP: "10.0.0.1", Port: 443, Pod: podWithSpec},
				{IP: "10.0.0.2", Port: 443, Pod: podWithoutSpec},
			},
			expected: 2,
			wantPod:  "",
		},
		{
			name: "duplicate: pod with spec wins over pod without spec",
			jobs: []ScanJob{
				{IP: sharedIP, Port: port, Pod: podWithoutSpec},
				{IP: sharedIP, Port: port, Pod: podWithSpec},
			},
			expected: 1,
			wantPod:  "node-exporter",
		},
		{
			name: "duplicate: both pods declare port, first wins",
			jobs: []ScanJob{
				{IP: sharedIP, Port: port, Pod: podWithSpec},
				{IP: sharedIP, Port: port, Pod: podAlsoWithSpec},
			},
			expected: 1,
			wantPod:  "node-exporter",
		},
		{
			name: "duplicate: pod without spec first, then pod with spec replaces it",
			jobs: []ScanJob{
				{IP: sharedIP, Port: port, Pod: podWithoutSpec},
				{IP: sharedIP, Port: port, Pod: podWithSpec},
			},
			expected: 1,
			wantPod:  "node-exporter",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := deduplicateScanJobs(tt.jobs)
			if len(result) != tt.expected {
				t.Errorf("expected %d jobs after dedup, got %d", tt.expected, len(result))
			}
			if tt.wantPod != "" && len(result) > 0 {
				if result[0].Pod.Name != tt.wantPod {
					t.Errorf("expected pod %s to be selected, got %s", tt.wantPod, result[0].Pod.Name)
				}
			}
		})
	}
}

func TestGetMinVersionValue(t *testing.T) {
	t.Parallel()

	if got := getMinVersionValue(nil); got != 0 {
		t.Fatalf("expected 0 for empty versions, got %d", got)
	}

	got := getMinVersionValue([]string{"TLSv1.3", "TLSv1.1", "TLSv1.2"})
	if got != 11 {
		t.Fatalf("expected minimum version value 11, got %d", got)
	}
}

func TestStringInSlice(t *testing.T) {
	t.Parallel()
	if !slices.Contains([]string{"a", "b", "c"}, "b") {
		t.Fatal("expected to find value in slice")
	}
	if slices.Contains([]string{"a", "b", "c"}, "z") {
		t.Fatal("expected value not to be present")
	}
}

func TestExtractTLSInfo(t *testing.T) {
	t.Parallel()

	scan := ScanRun{
		Hosts: []Host{{
			Ports: []Port{{
				Scripts: []Script{{
					ID: "ssl-enum-ciphers",
					Tables: []Table{
						{
							Key: "TLSv1.2",
							Tables: []Table{{
								Key: "ciphers",
								Tables: []Table{
									{Elems: []Elem{{Key: "name", Value: "CIPHER_A"}, {Key: "strength", Value: "A"}}},
									{Elems: []Elem{{Key: "name", Value: "CIPHER_A"}, {Key: "strength", Value: "A"}}},
								},
							}},
						},
						{Key: "TLSv1.3"},
					},
				}},
			}},
		}},
	}

	versions := ExtractTLSInfo(scan)
	slices.Sort(versions)

	if !reflect.DeepEqual(versions, []string{"TLSv1.2", "TLSv1.3"}) {
		t.Fatalf("unexpected versions: %#v", versions)
	}
}

func TestGroupTestSSLOutputByPort(t *testing.T) {
	t.Parallel()

	raw := []map[string]any{
		{"ip": "1.2.3.4", "port": "443", "id": "TLS1_3"},
		{"ip": "1.2.3.4", "port": "8443", "id": "TLS1_2"},
		{"ip": "1.2.3.4", "id": "NO_PORT"},
	}
	b, _ := json.Marshal(raw)

	grouped, err := GroupTestSSLOutputByPort(b)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(grouped) != 2 {
		t.Fatalf("expected 2 grouped ports, got %d", len(grouped))
	}
	if _, ok := grouped["443"]; !ok {
		t.Fatal("expected 443 group to exist")
	}
	if _, ok := grouped["8443"]; !ok {
		t.Fatal("expected 8443 group to exist")
	}
}

func TestGroupTestSSLOutputByIPPort(t *testing.T) {
	t.Parallel()

	raw := []map[string]any{
		{"ip": "1.2.3.4", "port": "443"},
		{"ip": "1.2.3.4", "port": "8443"},
		{"port": "443"},
	}
	b, _ := json.Marshal(raw)

	grouped, err := GroupTestSSLOutputByIPPort(b)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(grouped) != 2 {
		t.Fatalf("expected 2 grouped keys, got %d", len(grouped))
	}
	if _, ok := grouped["1.2.3.4:443"]; !ok {
		t.Fatal("expected 1.2.3.4:443 group")
	}
}

func TestParseTestSSLOutputAndConvert(t *testing.T) {
	t.Parallel()

	raw := []map[string]any{
		{"id": "TLS1_3", "finding": "offered (OK)", "severity": "OK"},
		{"id": "cipher-tls1_3_x1301", "finding": "TLS_AES_128_GCM_SHA256", "severity": "LOW"},
		{"id": "cipher_order", "finding": "irrelevant", "severity": "LOW"},
	}
	b, _ := json.Marshal(raw)

	run := ParseTestSSLOutput(b, "10.0.0.1", "443")
	versions := ExtractTLSInfo(run)
	if len(versions) == 0 || versions[0] != "TLSv1.3" {
		t.Fatalf("expected TLSv1.3 in parsed versions, got %#v", versions)
	}
}

func TestParseTestSSLOutputInvalidJSONFallback(t *testing.T) {
	t.Parallel()
	run := ParseTestSSLOutput([]byte("{not-json"), "host", "9443")
	if len(run.Hosts) == 0 || len(run.Hosts[0].Ports) == 0 {
		t.Fatal("expected fallback host/port in parse failure")
	}
	if run.Hosts[0].Ports[0].PortID != "9443" {
		t.Fatalf("expected fallback port 9443, got %s", run.Hosts[0].Ports[0].PortID)
	}
}

func TestParseTestSSLOutputFromFile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	file := filepath.Join(dir, "testssl.json")
	raw := []map[string]any{
		{"id": "TLS1_2", "finding": "offered (OK)", "severity": "OK"},
	}
	b, _ := json.Marshal(raw)
	if err := os.WriteFile(file, b, 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}

	run := ParseTestSSLOutputFromFile(file, "127.0.0.1", "443")
	versions := ExtractTLSInfo(run)
	if len(versions) != 1 || versions[0] != "TLSv1.2" {
		t.Fatalf("unexpected versions from file parse: %#v", versions)
	}
}

func TestExtractCipherAndVersionHelpers(t *testing.T) {
	t.Parallel()

	if got := extractCipherName("foo TLS_AES_128_GCM_SHA256"); got != "TLS_AES_128_GCM_SHA256" {
		t.Fatalf("unexpected cipher extraction: %s", got)
	}
	if got := extractCipherName(""); got != "" {
		t.Fatalf("expected empty cipher name, got %q", got)
	}

	if !isProtocolID("TLS1_3") || !isProtocolID("sslv3") {
		t.Fatal("expected protocol IDs to be detected")
	}
	if isProtocolID("cipher-tls1_3_x1301") {
		t.Fatal("unexpected protocol ID detection for cipher")
	}

	if got := extractTLSVersion("TLS1_3"); got != "TLSv1.3" {
		t.Fatalf("unexpected TLS version: %s", got)
	}
	if got := extractTLSVersion("sslv2"); got != "SSLv2" {
		t.Fatalf("unexpected SSL version: %s", got)
	}
	if got := extractTLSVersion("none"); got != "" {
		t.Fatalf("expected empty version, got %s", got)
	}

	if got := extractTLSVersionFromCipherID("cipher-tls1_3_x1301", map[string]any{}); got != "TLSv1.3" {
		t.Fatalf("unexpected version from cipher id: %s", got)
	}
	if got := extractTLSVersionFromCipherID("cipher-foo", map[string]any{"section": "TLS1_1"}); got != "TLSv1.1" {
		t.Fatalf("unexpected version from section: %s", got)
	}
	if got := extractTLSVersionFromCipherID("cipher-foo", map[string]any{"finding": "TLS_AES_256_GCM_SHA384"}); got != "TLSv1.3" {
		t.Fatalf("unexpected default tls13 inference: %s", got)
	}
	if got := extractTLSVersionFromCipherID("cipher-foo", map[string]any{}); got != "TLSv1.2" {
		t.Fatalf("unexpected fallback version: %s", got)
	}
}

func TestExtractCiphersFromTestSSL(t *testing.T) {
	t.Parallel()

	raw := []map[string]any{
		{"id": "TLS1_3", "finding": "offered (OK)", "severity": "OK"},
		{"id": "cipher-tls1_3_x1302", "finding": "TLS 1.3   x1302   TLS_AES_256_GCM_SHA384            ECDH 253   AESGCM      256      TLS_AES_256_GCM_SHA384", "severity": "OK"},
		{"id": "cipher-tls1_3_x1301", "finding": "TLS 1.3   x1301   TLS_AES_128_GCM_SHA256            ECDH 253   AESGCM      128      TLS_AES_128_GCM_SHA256", "severity": "OK"},
		{"id": "cipher-tls1_2_xc02f", "finding": "TLS 1.2   xc02f   ECDHE-RSA-AES128-GCM-SHA256       ECDH 253   AESGCM      128      TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "severity": "OK"},
		{"id": "cipher-tls1_3_x1301", "finding": "TLS 1.3   x1301   TLS_AES_128_GCM_SHA256            ECDH 253   AESGCM      128      TLS_AES_128_GCM_SHA256", "severity": "OK"},
		{"id": "cipher_order", "finding": "server", "severity": "OK"},
		{"id": "FS", "finding": "offered", "severity": "OK"},
	}
	b, _ := json.Marshal(raw)
	ciphers := ExtractCiphersFromTestSSL(b)

	if len(ciphers) != 3 {
		t.Fatalf("expected 3 unique ciphers, got %d: %#v", len(ciphers), ciphers)
	}
	expected := []string{"TLS_AES_256_GCM_SHA384", "TLS_AES_128_GCM_SHA256", "ECDHE-RSA-AES128-GCM-SHA256"}
	for _, e := range expected {
		if !slices.Contains(ciphers, e) {
			t.Fatalf("expected cipher %q in result, got %#v", e, ciphers)
		}
	}
}

func TestExtractCiphersFromTestSSLEmpty(t *testing.T) {
	t.Parallel()

	raw := []map[string]any{
		{"id": "TLS1_3", "finding": "offered (OK)", "severity": "OK"},
		{"id": "FS", "finding": "offered", "severity": "OK"},
	}
	b, _ := json.Marshal(raw)
	ciphers := ExtractCiphersFromTestSSL(b)
	if len(ciphers) != 0 {
		t.Fatalf("expected no ciphers from non-cipher findings, got %#v", ciphers)
	}
}

func TestExtractCiphersFromTestSSLInvalidJSON(t *testing.T) {
	t.Parallel()
	ciphers := ExtractCiphersFromTestSSL([]byte("{bad-json"))
	if ciphers != nil {
		t.Fatalf("expected nil for invalid JSON, got %#v", ciphers)
	}
}

func TestMapSeverityToStrength(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"OK":       "A",
		"LOW":      "A",
		"MEDIUM":   "B",
		"HIGH":     "C",
		"CRITICAL": "F",
		"UNKNOWN":  "unknown",
	}
	for sev, expected := range cases {
		if got := mapSeverityToStrength(sev); got != expected {
			t.Fatalf("severity %s -> expected %s, got %s", sev, expected, got)
		}
	}
}

func TestExtractKeyExchangeFromTestSSL(t *testing.T) {
	t.Parallel()

	raw := []map[string]any{
		{"id": "FS", "finding": "offered"},
		{"id": "FS_ECDHE", "finding": "x25519 secp256r1"},
		{"id": "FS_KEMs", "finding": "X25519MLKEM768"},
		{"id": "supported_groups", "finding": "x25519 secp256r1 X25519MLKEM768"},
		{"id": "group_mlkem768", "finding": "offered"},
	}
	b, _ := json.Marshal(raw)
	ke := ExtractKeyExchangeFromTestSSL(b)
	if ke == nil {
		t.Fatal("expected key exchange info")
	}
	if !ke.ForwardSecrecy.Supported {
		t.Fatal("expected forward secrecy supported")
	}
	if !slices.Contains(ke.ForwardSecrecy.KEMs, "X25519MLKEM768") || !slices.Contains(ke.ForwardSecrecy.KEMs, "mlkem768") {
		t.Fatalf("expected KEMs to be detected, got %#v", ke.ForwardSecrecy.KEMs)
	}
	if !slices.Contains(ke.Groups, "x25519") {
		t.Fatalf("expected supported group x25519, got %#v", ke.Groups)
	}
}

func TestExtractKeyExchangeFromTestSSLNoData(t *testing.T) {
	t.Parallel()
	raw := []map[string]any{
		{"id": "FS", "finding": "not offered"},
	}
	b, _ := json.Marshal(raw)
	if got := ExtractKeyExchangeFromTestSSL(b); got != nil {
		t.Fatalf("expected nil key exchange for no useful data, got %#v", got)
	}
}

func TestIsKEMGroup(t *testing.T) {
	t.Parallel()
	if !IsKEMGroup("x25519MLKEM768") {
		t.Fatal("expected mlkem group to be true")
	}
	if !IsKEMGroup("sntrup761") {
		t.Fatal("expected sntrup group to be true")
	}
	if IsKEMGroup("secp256r1") {
		t.Fatal("expected classical group to be false")
	}
}

func TestLimitPodsToIPCount(t *testing.T) {
	t.Parallel()

	pods := []k8s.PodInfo{
		{Name: "a", IPs: []string{"1.1.1.1", "1.1.1.2"}},
		{Name: "b", IPs: []string{"2.2.2.2", "2.2.2.3"}},
	}

	if got := LimitPodsToIPCount(pods, 0); len(got) != 2 {
		t.Fatalf("expected unchanged pods for non-positive limit, got %d", len(got))
	}

	got := LimitPodsToIPCount(pods, 3)
	if len(got) != 2 {
		t.Fatalf("expected 2 pods with second truncated, got %d", len(got))
	}
	if len(got[1].IPs) != 1 || got[1].IPs[0] != "2.2.2.2" {
		t.Fatalf("expected truncated pod IP list, got %#v", got[1].IPs)
	}
}

func TestWriteTargetsFile(t *testing.T) {
	t.Parallel()

	name, err := writeTargetsFile([]string{"a:443", "b:8443"})
	if err != nil {
		t.Fatalf("unexpected error writing targets file: %v", err)
	}
	defer os.Remove(name)

	b, err := os.ReadFile(name)
	if err != nil {
		t.Fatalf("read targets file: %v", err)
	}
	got := strings.TrimSpace(string(b))
	if got != "a:443\nb:8443" {
		t.Fatalf("unexpected targets file content: %q", got)
	}
}

func TestDiscoverPortsFromPodSpec(t *testing.T) {
	t.Parallel()

	pod := &v1.Pod{
		Spec: v1.PodSpec{
			Containers: []v1.Container{
				{
					Ports: []v1.ContainerPort{
						{ContainerPort: 8443, Protocol: v1.ProtocolTCP},
						{ContainerPort: 53, Protocol: v1.ProtocolUDP},
					},
				},
			},
			InitContainers: []v1.Container{
				{
					Ports: []v1.ContainerPort{
						{ContainerPort: 9443, Protocol: v1.ProtocolTCP},
					},
				},
			},
		},
	}

	ports, err := k8s.DiscoverPortsFromPodSpec(pod)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !reflect.DeepEqual(ports, []int{8443, 9443}) {
		t.Fatalf("unexpected discovered ports: %#v", ports)
	}
}

func TestFilterByProcessPorts(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		ownedPorts map[int]bool
		procPorts  []int
		specPorts  []int
		want       []int
	}{
		{
			name:       "keeps process-mapped ports",
			ownedPorts: map[int]bool{9091: true, 9043: true},
			procPorts:  []int{9091, 9043, 6443, 10257},
			specPorts:  []int{9091, 9043},
			want:       []int{9091, 9043},
		},
		{
			name:       "spec-declared port preserved when process map misses it",
			ownedPorts: map[int]bool{9091: true, 9043: true},
			procPorts:  []int{9091, 9043, 8443, 6443, 10257},
			specPorts:  []int{9091, 9043, 8443},
			want:       []int{9091, 9043, 8443},
		},
		{
			name:       "unowned port not in spec still dropped",
			ownedPorts: map[int]bool{9091: true},
			procPorts:  []int{9091, 6443, 10257},
			specPorts:  []int{9091},
			want:       []int{9091},
		},
		{
			name:       "nil specPorts — only process-owned ports kept",
			ownedPorts: map[int]bool{9091: true},
			procPorts:  []int{9091, 6443, 10257},
			specPorts:  nil,
			want:       []int{9091},
		},
		{
			name:       "ports owned by another pod are not credited to this one",
			ownedPorts: map[int]bool{9212: true},
			procPorts:  []int{9212, 9103, 9105, 9108},
			specPorts:  nil,
			want:       []int{9212},
		},
		{
			// A successfully discovered but empty ownership set (e.g. every
			// listening socket's inode belongs to another container's PID
			// namespace) must still be filtered down to only the ports declared
			// by secondary containers — it is not evidence that discovery was
			// unavailable, and must not fall back to keeping every proc port.
			name:       "empty but non-nil ownedPorts still filters down to secondary spec ports",
			ownedPorts: map[int]bool{},
			procPorts:  []int{9100, 9101, 9102},
			specPorts:  []int{9101},
			want:       []int{9101},
		},
		{
			name:       "empty but non-nil ownedPorts with no spec ports drops everything",
			ownedPorts: map[int]bool{},
			procPorts:  []int{9100, 9101, 9102},
			specPorts:  nil,
			want:       nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := filterByProcessPorts(tt.ownedPorts, tt.procPorts, tt.specPorts)
			slices.Sort(got)
			slices.Sort(tt.want)
			if !slices.Equal(got, tt.want) {
				t.Errorf("filterByProcessPorts() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestHasPQCComplianceFailures(t *testing.T) {
	t.Parallel()

	noPorts := ScanResults{
		IPResults: []IPResult{{
			IP: "1.1.1.1",
			PortResults: []PortResult{{
				Status: StatusNoPorts,
			}},
		}},
	}
	if hasPQCComplianceFailures(noPorts) {
		t.Fatal("expected no failure for no-ports status")
	}

	noTLS13 := ScanResults{
		IPResults: []IPResult{{
			IP: "1.1.1.1",
			PortResults: []PortResult{{
				Port:           443,
				TLS13Supported: false,
				MLKEMSupported: true,
				MLKEMCiphers:   []string{"x25519mlkem768"},
			}},
		}},
	}
	if !hasPQCComplianceFailures(noTLS13) {
		t.Fatal("expected failure when tls13 is false")
	}

	noMLKEM := ScanResults{
		IPResults: []IPResult{{
			IP: "1.1.1.1",
			PortResults: []PortResult{{
				Port:           443,
				TLS13Supported: true,
				MLKEMSupported: false,
			}},
		}},
	}
	if !hasPQCComplianceFailures(noMLKEM) {
		t.Fatal("expected failure when mlkem supported is false")
	}

	valid := ScanResults{
		IPResults: []IPResult{{
			IP: "1.1.1.1",
			PortResults: []PortResult{{
				Port:           443,
				TLS13Supported: true,
				MLKEMSupported: true,
				MLKEMCiphers:   []string{"X25519MLKEM768"},
			}},
		}},
	}
	if hasPQCComplianceFailures(valid) {
		t.Fatal("expected no pqc failures for tls13 + valid mlkem")
	}
}
