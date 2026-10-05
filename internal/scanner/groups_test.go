package scanner

import "testing"

func TestNormalizeGroupName(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"X25519MLKEM768", "x25519mlkem768"},
		{"x25519-mlkem768", "x25519mlkem768"},
		{"x25519_mlkem768", "x25519mlkem768"},
		{" secp256r1 ", "secp256r1"},
	}
	for _, tc := range cases {
		if got := NormalizeGroupName(tc.in); got != tc.want {
			t.Errorf("NormalizeGroupName(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestParseExpectedGroups(t *testing.T) {
	got := ParseExpectedGroups(" X25519MLKEM768, x25519 , ,secp256r1 ")
	want := []string{"X25519MLKEM768", "x25519", "secp256r1"}
	if len(got) != len(want) {
		t.Fatalf("got %#v, want %#v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %#v, want %#v", got, want)
		}
	}
}

func TestParseGroupsCheckMode(t *testing.T) {
	m, err := ParseGroupsCheckMode("contains")
	if err != nil || m != GroupsModeContains {
		t.Fatalf("contains: got %q err=%v", m, err)
	}
	m, err = ParseGroupsCheckMode("exact")
	if err != nil || m != GroupsModeExact {
		t.Fatalf("exact: got %q err=%v", m, err)
	}
	m, err = ParseGroupsCheckMode("")
	if err != nil || m != GroupsModeContains {
		t.Fatalf("empty: got %q err=%v", m, err)
	}
	if _, err := ParseGroupsCheckMode("subset"); err == nil {
		t.Fatal("expected error for invalid mode")
	}
}

func TestCheckExpectedGroupsContains(t *testing.T) {
	observed := []string{"x25519", "secp256r1", "X25519MLKEM768"}
	if !CheckExpectedGroups(observed, []string{"X25519MLKEM768", "x25519"}, GroupsModeContains) {
		t.Fatal("contains should pass when required groups are present")
	}
	if CheckExpectedGroups(observed, []string{"X25519MLKEM768", "missing"}, GroupsModeContains) {
		t.Fatal("contains should fail when a required group is missing")
	}
	if !CheckExpectedGroups(observed, nil, GroupsModeContains) {
		t.Fatal("empty expected should always pass")
	}
}

func TestCheckExpectedGroupsExact(t *testing.T) {
	observed := []string{"x25519", "X25519MLKEM768"}
	if !CheckExpectedGroups(observed, []string{"X25519MLKEM768", "x25519"}, GroupsModeExact) {
		t.Fatal("exact should pass for same set in different order/case")
	}
	if CheckExpectedGroups(observed, []string{"x25519"}, GroupsModeExact) {
		t.Fatal("exact should fail when extras are present")
	}
	if CheckExpectedGroups([]string{"x25519"}, []string{"x25519", "X25519MLKEM768"}, GroupsModeExact) {
		t.Fatal("exact should fail when expected group is missing")
	}
}

func TestHasExpectedGroupsFailures(t *testing.T) {
	results := ScanResults{
		IPResults: []IPResult{{
			IP: "10.0.0.1",
			PortResults: []PortResult{{
				Port:   6443,
				Status: StatusOK,
				TlsKeyExchange: &KeyExchangeInfo{
					Groups: []string{"x25519", "secp256r1"},
				},
			}},
		}},
	}

	if !HasExpectedGroupsFailures(results, []string{"X25519MLKEM768"}, GroupsModeContains, SkipUnscannable) {
		t.Fatal("expected failure when ML-KEM group missing")
	}
	if HasExpectedGroupsFailures(results, []string{"x25519"}, GroupsModeContains, SkipUnscannable) {
		t.Fatal("expected pass when x25519 present")
	}

	// Unscannable ports are skipped.
	skipResults := ScanResults{
		IPResults: []IPResult{{
			IP: "10.0.0.2",
			PortResults: []PortResult{{
				Port:   8080,
				Status: StatusNoTLS,
				TlsKeyExchange: &KeyExchangeInfo{
					Groups: nil,
				},
			}},
		}},
	}
	if HasExpectedGroupsFailures(skipResults, []string{"x25519"}, GroupsModeContains, SkipUnscannable) {
		t.Fatal("NO_TLS ports should be skipped")
	}
}
