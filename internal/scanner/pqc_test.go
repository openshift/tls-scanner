package scanner

import (
	"reflect"
	"testing"
)

func port(status ScanStatus, tls13, mlkem bool) PortResult {
	return PortResult{Status: status, TLS13Supported: tls13, MLKEMSupported: mlkem}
}

func TestCountPortsByStatus(t *testing.T) {
	cases := []struct {
		name    string
		results ScanResults
		want    map[ScanStatus]int
	}{
		{
			name:    "no results",
			results: ScanResults{},
			want:    map[ScanStatus]int{},
		},
		{
			name: "aggregates across IPs",
			results: ScanResults{IPResults: []IPResult{
				{PortResults: []PortResult{port(StatusOK, true, false), port(StatusNoTLS, false, false)}},
				{PortResults: []PortResult{port(StatusOK, true, true), port(StatusLocalhostOnly, false, false)}},
			}},
			want: map[ScanStatus]int{StatusOK: 2, StatusNoTLS: 1, StatusLocalhostOnly: 1},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := CountPortsByStatus(tc.results); !reflect.DeepEqual(got, tc.want) {
				t.Errorf("CountPortsByStatus() = %#v, want %#v", got, tc.want)
			}
		})
	}
}

func TestSummarizePQC(t *testing.T) {
	cases := []struct {
		name    string
		results ScanResults
		want    PQCSummary
	}{
		{
			name:    "no results",
			results: ScanResults{},
			want: PQCSummary{
				SkippedByStatus: map[ScanStatus]int{},
			},
		},
		{
			// Skipped ports must never contribute to the readiness numerators
			// or be reported as failures.
			name: "skipped statuses are excluded from readiness counts",
			results: ScanResults{IPResults: []IPResult{
				{PortResults: []PortResult{
					port(StatusOK, true, true),
					port(StatusOK, true, false),
					port(StatusOK, false, false), // TLS 1.2 only
					port(StatusNoTLS, false, false),
					port(StatusLocalhostOnly, false, false),
					port(StatusProbePort, false, false),
					{Status: StatusNoPorts, Port: 0},
				}},
			}},
			want: PQCSummary{
				Scanned:    3,
				Skipped:    4,
				TLS13Ready: 2,
				MLKEMReady: 1,
				PQCReady:   1,
				SkippedByStatus: map[ScanStatus]int{
					StatusNoTLS:         1,
					StatusLocalhostOnly: 1,
					StatusProbePort:     1,
					StatusNoPorts:       1,
				},
			},
		},
		{
			name: "aggregates across multiple IPs",
			results: ScanResults{IPResults: []IPResult{
				{PortResults: []PortResult{port(StatusOK, true, true)}},
				{PortResults: []PortResult{port(StatusNoTLS, false, false)}},
			}},
			want: PQCSummary{
				Scanned:    1,
				Skipped:    1,
				TLS13Ready: 1,
				MLKEMReady: 1,
				PQCReady:   1,
				SkippedByStatus: map[ScanStatus]int{
					StatusNoTLS: 1,
				},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := SummarizePQC(tc.results); !reflect.DeepEqual(got, tc.want) {
				t.Errorf("SummarizePQC() = %#v, want %#v", got, tc.want)
			}
		})
	}
}
