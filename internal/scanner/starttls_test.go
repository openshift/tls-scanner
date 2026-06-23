package scanner

import (
	"testing"
)

func TestStarttlsProtoForProcess(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		comm string
		want string
	}{
		{"postgres", "postgres"},
		{"postmaster", "postgres"},
		{"pgbouncer", "postgres"},
		{"mysqld", "mysql"},
		{"mariadbd", "mysql"},
		{"nginx", ""},
		{"", ""},
	} {
		if got := StarttlsProtoForProcess(tc.comm); got != tc.want {
			t.Errorf("StarttlsProtoForProcess(%q) = %q, want %q", tc.comm, got, tc.want)
		}
	}
}

func TestParseStarttlsPorts(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    StarttlsPorts
		wantErr bool
	}{
		{
			name:  "empty string",
			input: "",
			want:  nil,
		},
		{
			name:  "single protocol single port",
			input: "postgres=5432",
			want:  StarttlsPorts{5432: "postgres"},
		},
		{
			name:  "single protocol multiple ports",
			input: "postgres=5432:6432",
			want:  StarttlsPorts{5432: "postgres", 6432: "postgres"},
		},
		{
			name:  "multiple protocols",
			input: "postgres=5432,mysql=3306,smtp=25",
			want:  StarttlsPorts{5432: "postgres", 3306: "mysql", 25: "smtp"},
		},
		{
			name:  "multiple protocols with multiple ports",
			input: "postgres=5432:6432,mysql=3306:3307",
			want:  StarttlsPorts{5432: "postgres", 6432: "postgres", 3306: "mysql", 3307: "mysql"},
		},
		{
			name:  "whitespace is trimmed",
			input: " postgres = 5432 , mysql = 3306 ",
			want:  StarttlsPorts{5432: "postgres", 3306: "mysql"},
		},
		{
			name:    "unknown protocol",
			input:   "bogus=5432",
			wantErr: true,
		},
		{
			name:    "invalid port",
			input:   "postgres=abc",
			wantErr: true,
		},
		{
			name:    "port out of range",
			input:   "postgres=99999",
			wantErr: true,
		},
		{
			name:    "port zero",
			input:   "postgres=0",
			wantErr: true,
		},
		{
			name:    "missing port",
			input:   "postgres=",
			wantErr: true,
		},
		{
			name:    "missing protocol",
			input:   "=5432",
			wantErr: true,
		},
		{
			name:    "no equals sign",
			input:   "postgres5432",
			wantErr: true,
		},
		{
			name:    "conflicting port mapping",
			input:   "postgres=5432,mysql=5432",
			wantErr: true,
		},
		{
			name:  "same protocol same port is ok",
			input: "postgres=5432,postgres=5432",
			want:  StarttlsPorts{5432: "postgres"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseStarttlsPorts(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ParseStarttlsPorts(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if len(got) != len(tt.want) {
				t.Fatalf("ParseStarttlsPorts(%q) = %v, want %v", tt.input, got, tt.want)
			}
			for port, proto := range tt.want {
				if got[port] != proto {
					t.Errorf("ParseStarttlsPorts(%q)[%d] = %q, want %q", tt.input, port, got[port], proto)
				}
			}
		})
	}
}
