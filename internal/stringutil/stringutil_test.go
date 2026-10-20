package stringutil

import (
	"testing"
)

func TestNormalizeHost(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   string
		want string
	}{
		{"plain IPv4", "10.0.0.1", "10.0.0.1"},
		{"bracketed IPv6", "[::1]", "::1"},
		{"bracketed full IPv6", "[fd2e:6f44:5dd8::16]", "fd2e:6f44:5dd8::16"},
		{"no brackets", "fd2e:6f44:5dd8::16", "fd2e:6f44:5dd8::16"},
		{"whitespace trimmed", "  10.0.0.1  ", "10.0.0.1"},
		{"whitespace with brackets", "  [::1]  ", "::1"},
		{"empty string", "", ""},
		{"single bracket only", "[", "["},
		{"hostname", "example.com", "example.com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := NormalizeHost(tt.in); got != tt.want {
				t.Errorf("NormalizeHost(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestRemoveDuplicates(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   []string
		want []string
	}{
		{"no duplicates", []string{"a", "b", "c"}, []string{"a", "b", "c"}},
		{"all duplicates", []string{"a", "a", "a"}, []string{"a"}},
		{"mixed", []string{"a", "b", "a", "c", "b"}, []string{"a", "b", "c"}},
		{"empty strings filtered", []string{"a", "", "b", ""}, []string{"a", "b"}},
		{"nil slice", nil, nil},
		{"empty slice", []string{}, nil},
		{"single element", []string{"x"}, []string{"x"}},
		{"only empty strings", []string{"", "", ""}, nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := RemoveDuplicates(tt.in)
			if len(got) != len(tt.want) {
				t.Fatalf("RemoveDuplicates(%v) = %v (len %d), want %v (len %d)", tt.in, got, len(got), tt.want, len(tt.want))
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("RemoveDuplicates(%v)[%d] = %q, want %q", tt.in, i, got[i], tt.want[i])
				}
			}
		})
	}
}
