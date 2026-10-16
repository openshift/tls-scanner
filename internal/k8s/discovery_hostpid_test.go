package k8s

import (
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// Run the actual discovery shell against a synthetic host /proc view. Both
// processes are visible, but only one belongs to the exec container's cgroup.
func TestProcDiscoveryHostPID(t *testing.T) {
	for _, tc := range []struct {
		name, own, flag string
		missing         bool
		want            map[uint64]string
		wantError       bool
	}{
		{name: "host PID cgroup v2", own: "0::/kubepods/pod-a/container-a\n", flag: "true", want: map[uint64]string{101: "ptp"}},
		{name: "host PID cgroup v1", own: "2:cpu:/pod-a/container-a\n3:memory:/pod-a/container-a\n", flag: "true", want: map[uint64]string{101: "ptp"}},
		{name: "private cgroup namespace", own: "0::/\n", flag: "true", want: map[uint64]string{101: "ptp"}},
		{name: "private PID behavior unchanged", own: "0::/pod-a/container-a\n", flag: "false", want: map[uint64]string{101: "ptp", 202: "unrelated"}},
		{name: "missing cgroup fails discovery", flag: "true", missing: true, wantError: true},
		{name: "empty cgroup fails discovery", flag: "true", wantError: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			write := func(name, value string) {
				t.Helper()
				path := filepath.Join(root, name)
				if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte(value), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if !tc.missing {
				write("self/cgroup", tc.own)
			}
			write("net/tcp", "")
			write("net/tcp6", "")
			for _, p := range []struct{ pid, comm, cgroup, inode string }{
				{"100", "ptp", tc.own, "101"},
				{"200", "unrelated", "0::/other-pod/other-container\n", "202"},
			} {
				write(p.pid+"/comm", p.comm+"\n")
				write(p.pid+"/cgroup", p.cgroup)
				if err := os.MkdirAll(filepath.Join(root, p.pid, "fd"), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink("socket:["+p.inode+"]", filepath.Join(root, p.pid, "fd", "3")); err != nil {
					t.Fatal(err)
				}
			}
			// Only replace the proc filesystem root; execute production shell logic.
			script := strings.ReplaceAll(procDiscoveryShell, "/proc/", root+"/")
			out, err := exec.Command("/bin/sh", "-c", script, "tls-scanner-proc", tc.flag).CombinedOutput()
			if tc.wantError {
				if err == nil {
					t.Fatal("expected discovery failure")
				}
				return
			}
			if err != nil {
				t.Fatalf("discovery: %v: %s", err, out)
			}
			_, inodePart := splitMergedProcOutput(string(out))
			if got := ParseInodeCommMap(inodePart); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("ownership: got %v, want %v", got, tc.want)
			}
		})
	}
}
