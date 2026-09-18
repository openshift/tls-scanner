package output

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/openshift/tls-scanner/internal/k8s"
	"github.com/openshift/tls-scanner/internal/scanner"
)

func testScanResults() scanner.ScanResults {
	return scanner.ScanResults{
		Timestamp:  "2026-05-13T12:00:00Z",
		TotalIPs:   1,
		ScannedIPs: 1,
		IPResults: []scanner.IPResult{{
			IP:     "10.0.0.1",
			Status: "scanned",
			Pod:    &k8s.PodInfo{Name: "pod-a", Namespace: "ns-a"},
			PortResults: []scanner.PortResult{{
				Port:     443,
				Protocol: "tcp",
				Service:  "https",
				Status:   scanner.StatusOK,
			}},
		}},
	}
}

func TestWriteJSONOutput(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "results.json")
	results := testScanResults()

	if err := WriteJSONOutput(results, path); err != nil {
		t.Fatalf("WriteJSONOutput returned error: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading output: %v", err)
	}

	var got scanner.ScanResults
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if got.Timestamp != "2026-05-13T12:00:00Z" {
		t.Errorf("Timestamp = %q, want %q", got.Timestamp, "2026-05-13T12:00:00Z")
	}
	if len(got.IPResults) != 1 {
		t.Fatalf("expected 1 IPResult, got %d", len(got.IPResults))
	}
	if got.IPResults[0].IP != "10.0.0.1" {
		t.Errorf("IP = %q, want %q", got.IPResults[0].IP, "10.0.0.1")
	}
}

func TestWriteOutputFilesNoop(t *testing.T) {
	t.Parallel()

	results := testScanResults()
	if err := WriteOutputFiles(results, t.TempDir(), "", "", "", "", false, nil); err != nil {
		t.Fatalf("expected nil for empty filenames, got: %v", err)
	}
}

func TestWriteOutputFilesJSON(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	results := testScanResults()
	if err := WriteOutputFiles(results, dir, "out.json", "", "", "", false, nil); err != nil {
		t.Fatalf("WriteOutputFiles returned error: %v", err)
	}

	path := filepath.Join(dir, "out.json")
	if _, err := os.Stat(path); err != nil {
		t.Errorf("expected JSON file at %s: %v", path, err)
	}
}

func TestWriteOutputFilesAbsolutePath(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	artifactDir := filepath.Join(dir, "artifacts")
	absPath := filepath.Join(dir, "absolute.json")
	results := testScanResults()
	if err := WriteOutputFiles(results, artifactDir, absPath, "", "", "", false, nil); err != nil {
		t.Fatalf("WriteOutputFiles returned error: %v", err)
	}

	if _, err := os.Stat(absPath); err != nil {
		t.Errorf("expected JSON file at absolute path %s: %v", absPath, err)
	}
}

func TestWriteOutputFilesCSV(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	results := testScanResults()
	if err := WriteOutputFiles(results, dir, "", "out.csv", "", "", false, nil); err != nil {
		t.Fatalf("WriteOutputFiles returned error: %v", err)
	}

	path := filepath.Join(dir, "out.csv")
	if _, err := os.Stat(path); err != nil {
		t.Errorf("expected CSV file at %s: %v", path, err)
	}
}

func TestWriteOutputFilesJUnit(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	results := testScanResults()
	if err := WriteOutputFiles(results, dir, "", "", "out.xml", "", false, nil); err != nil {
		t.Fatalf("WriteOutputFiles returned error: %v", err)
	}

	path := filepath.Join(dir, "out.xml")
	if _, err := os.Stat(path); err != nil {
		t.Errorf("expected JUnit file at %s: %v", path, err)
	}
}
