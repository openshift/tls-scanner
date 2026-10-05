package scanner

import (
	"fmt"
	"log/slog"
	"slices"
	"strings"
)

// GroupsCheckMode controls how --expected-groups is evaluated against
// observed TLS named groups / curves from testssl.
type GroupsCheckMode string

const (
	// GroupsModeContains requires every expected group to be present among
	// observed groups (extras are allowed).
	GroupsModeContains GroupsCheckMode = "contains"
	// GroupsModeExact requires the observed group set to match the expected
	// set exactly after normalization (order ignored).
	GroupsModeExact GroupsCheckMode = "exact"
)

// ParseGroupsCheckMode validates a user-supplied mode string.
func ParseGroupsCheckMode(s string) (GroupsCheckMode, error) {
	switch GroupsCheckMode(strings.ToLower(strings.TrimSpace(s))) {
	case "", GroupsModeContains:
		return GroupsModeContains, nil
	case GroupsModeExact:
		return GroupsModeExact, nil
	default:
		return "", fmt.Errorf("invalid expected-groups-mode %q (valid: contains, exact)", s)
	}
}

// ParseExpectedGroups splits a comma-separated list and drops empty entries.
func ParseExpectedGroups(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// NormalizeGroupName lowercases and strips separators so X25519MLKEM768,
// x25519-mlkem768, and x25519_mlkem768 compare equal.
func NormalizeGroupName(name string) string {
	n := strings.ToLower(strings.TrimSpace(name))
	n = strings.ReplaceAll(n, "-", "")
	n = strings.ReplaceAll(n, "_", "")
	n = strings.ReplaceAll(n, " ", "")
	return n
}

// ObservedGroups returns the named groups / curves advertised by the endpoint.
func ObservedGroups(pr PortResult) []string {
	if pr.TlsKeyExchange == nil {
		return nil
	}
	return slices.Clone(pr.TlsKeyExchange.Groups)
}

func normalizedSet(names []string) map[string]struct{} {
	set := make(map[string]struct{}, len(names))
	for _, n := range names {
		norm := NormalizeGroupName(n)
		if norm != "" {
			set[norm] = struct{}{}
		}
	}
	return set
}

// CheckExpectedGroups evaluates observed groups against expected.
// An empty expected list always passes.
func CheckExpectedGroups(observed, expected []string, mode GroupsCheckMode) bool {
	if len(expected) == 0 {
		return true
	}
	if mode == "" {
		mode = GroupsModeContains
	}

	obs := normalizedSet(observed)
	exp := normalizedSet(expected)

	switch mode {
	case GroupsModeExact:
		if len(obs) != len(exp) {
			return false
		}
		for g := range exp {
			if _, ok := obs[g]; !ok {
				return false
			}
		}
		return true
	default: // contains
		for g := range exp {
			if _, ok := obs[g]; !ok {
				return false
			}
		}
		return true
	}
}

// HasExpectedGroupsFailures returns true when any scannable endpoint fails the
// expected-groups policy.
func HasExpectedGroupsFailures(results ScanResults, expected []string, mode GroupsCheckMode, skip PortFilter) bool {
	if len(expected) == 0 {
		return false
	}
	if mode == "" {
		mode = GroupsModeContains
	}

	for _, ipResult := range results.IPResults {
		for _, portResult := range ipResult.PortResults {
			if skip != nil && skip(portResult.Status) {
				continue
			}
			observed := ObservedGroups(portResult)
			if CheckExpectedGroups(observed, expected, mode) {
				continue
			}
			slog.Warn("expected-groups check failed",
				"ip", ipResult.IP,
				"port", portResult.Port,
				"mode", mode,
				"expected", expected,
				"observed", observed,
			)
			return true
		}
	}
	return false
}
