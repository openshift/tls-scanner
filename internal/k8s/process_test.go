package k8s

import (
	"testing"
)

// newTestClient returns a Client with all internal maps initialised, suitable
// for unit tests that don't need a real Kubernetes API server.
func newTestClient() *Client {
	return &Client{
		processNameMap:    make(map[string]map[int]string),
		listenInfoMap:     make(map[string]map[int]ListenInfo),
		procListenAddrMap: make(map[string]map[int]string),
		podOwnedPorts:     make(map[string]map[int]bool),
	}
}

func TestIsLocalhostOnly_procData(t *testing.T) {
	c := newTestClient()

	c.procListenAddrMap["10.0.0.1"] = map[int]string{
		9259: "127.0.0.1",
		9258: "0.0.0.0",
	}

	tests := []struct {
		port     int
		wantIs   bool
		wantAddr string
	}{
		{9259, true, "127.0.0.1"},
		{9258, false, ""},
		{9999, false, ""},
	}

	for _, tt := range tests {
		gotIs, gotAddr := c.IsLocalhostOnly("10.0.0.1", tt.port)
		if gotIs != tt.wantIs || gotAddr != tt.wantAddr {
			t.Errorf("IsLocalhostOnly(port=%d) = (%v, %q), want (%v, %q)",
				tt.port, gotIs, gotAddr, tt.wantIs, tt.wantAddr)
		}
	}
}

func TestIsLocalhostOnly_ipv6Localhost(t *testing.T) {
	c := newTestClient()

	c.procListenAddrMap["10.0.0.2"] = map[int]string{
		8080: "::1",
	}

	gotIs, gotAddr := c.IsLocalhostOnly("10.0.0.2", 8080)
	if !gotIs || gotAddr != "::1" {
		t.Errorf("IsLocalhostOnly() = (%v, %q), want (true, %q)", gotIs, gotAddr, "::1")
	}
}

func TestCacheProcListenInfo(t *testing.T) {
	c := newTestClient()
	pod := PodInfo{IPs: []string{"10.0.0.1"}}
	entries := map[int]ProcListenEntry{
		443:  {Addr: "0.0.0.0", Inode: 12345},
		8080: {Addr: "127.0.0.1", Inode: 99}, // no inode mapping
	}
	inodeComm := map[uint64]string{12345: "nginx"}

	c.cacheProcListenInfo(pod, entries, inodeComm)

	if c.procListenAddrMap["10.0.0.1"][443] != "0.0.0.0" {
		t.Errorf("procListenAddrMap[443] = %q, want 0.0.0.0", c.procListenAddrMap["10.0.0.1"][443])
	}
	if c.processNameMap["10.0.0.1"][443] != "nginx" {
		t.Errorf("processNameMap[443] = %q, want nginx", c.processNameMap["10.0.0.1"][443])
	}
	if _, ok := c.processNameMap["10.0.0.1"][8080]; ok {
		t.Error("expected no process name for port without inode mapping")
	}
	if !c.podOwnedPorts[podOwnershipKey(pod)][443] {
		t.Error("expected port 443 to be recorded as owned by pod")
	}
	if c.podOwnedPorts[podOwnershipKey(pod)][8080] {
		t.Error("expected port 8080 (no inode mapping) to not be recorded as owned")
	}
}

func TestGetOwnedPorts(t *testing.T) {
	c := newTestClient()
	pod := PodInfo{Namespace: "ns", Name: "pod-a", IPs: []string{"10.0.0.1"}}
	entries := map[int]ProcListenEntry{
		443:  {Addr: "0.0.0.0", Inode: 1},
		8443: {Addr: "0.0.0.0", Inode: 2},
	}
	inodeComm := map[uint64]string{1: "nginx", 2: "sidecar"}
	c.cacheProcListenInfo(pod, entries, inodeComm)

	got := c.GetOwnedPorts(pod)
	if !got[443] || !got[8443] {
		t.Errorf("GetOwnedPorts() = %v, want ports 443 and 8443 owned", got)
	}

	other := PodInfo{Namespace: "ns", Name: "pod-b", IPs: []string{"10.0.0.2"}}
	if c.GetOwnedPorts(other) != nil {
		t.Error("expected nil for pod with no cached ownership data")
	}
}

// TestGetOwnedPorts_EmptyOwnershipIsNotNil reproduces a bug where a pod with
// non-empty /proc/net/tcp results but zero resolvable inode-to-process
// matches (e.g. every listening socket belongs to another container's PID
// namespace) was indistinguishable from a pod for which /proc discovery
// never ran at all. Both cases populated podOwnedPorts with an empty map,
// but GetOwnedPorts collapsed "discovered, nothing owned" into nil, which
// callers use as a signal to skip filtering entirely — silently letting
// unrelated host listeners through on hostNetwork pods.
func TestGetOwnedPorts_EmptyOwnershipIsNotNil(t *testing.T) {
	c := newTestClient()
	pod := PodInfo{Namespace: "ns", Name: "pod-c", IPs: []string{"10.0.0.3"}}

	// Non-empty /proc results (entries), but no inode resolves to a process
	// visible in this pod's own PID namespace.
	entries := map[int]ProcListenEntry{
		9100: {Addr: "0.0.0.0", Inode: 42},
	}
	inodeComm := map[uint64]string{} // no matches
	c.cacheProcListenInfo(pod, entries, inodeComm)

	got := c.GetOwnedPorts(pod)
	if got == nil {
		t.Fatal("GetOwnedPorts() = nil, want non-nil empty map for a pod with a successfully " +
			"populated but empty ownership set")
	}
	if len(got) != 0 {
		t.Errorf("GetOwnedPorts() = %v, want empty map", got)
	}

	// A pod for which discovery never ran must still report nil, so callers
	// can distinguish "no data" from "data says nothing is owned".
	neverDiscovered := PodInfo{Namespace: "ns", Name: "pod-d", IPs: []string{"10.0.0.4"}}
	if c.GetOwnedPorts(neverDiscovered) != nil {
		t.Error("expected nil for pod with no cached ownership data")
	}
}

// TestGetOwnedPorts_NoLeakAcrossUkrelatedHostNetworkPods reproduces a port
// misattribution bug when the pod is a hostNetwork pod.
func TestGetOwnedPorts_NoLeakAcrossUnrelatedHostNetworkPods(t *testing.T) {
	c := newTestClient()
	nodeIP := "10.0.1.5"

	ovnkubePod := PodInfo{Namespace: "openshift-ovn-kubernetes", Name: "ovnkube-node-abc12", IPs: []string{nodeIP}}
	ovnkubeEntries := map[int]ProcListenEntry{
		9103: {Addr: "0.0.0.0", Inode: 1},
		9105: {Addr: "0.0.0.0", Inode: 2},
	}
	ovnkubeInodeComm := map[uint64]string{1: "ovnkube-controller", 2: "ovnkube-controller"}
	c.cacheProcListenInfo(ovnkubePod, ovnkubeEntries, ovnkubeInodeComm)

	filestorePod := PodInfo{
		Namespace: "openshift-cluster-csi-drivers",
		Name:      "gcp-filestore-csi-driver-controller-548d7c67d6-db7tx",
		IPs:       []string{nodeIP},
	}
	filestoreEntries := map[int]ProcListenEntry{
		9212: {Addr: "0.0.0.0", Inode: 3},
	}
	filestoreInodeComm := map[uint64]string{3: "kube-rbac-proxy"}
	c.cacheProcListenInfo(filestorePod, filestoreEntries, filestoreInodeComm)

	owned := c.GetOwnedPorts(filestorePod)

	if owned[9103] {
		t.Error("GetOwnedPorts() for the filestore pod incorrectly includes port 9103, " +
			"owned by ovnkube-node, not the filestore controller (see issue #85)")
	}
	if owned[9105] {
		t.Error("GetOwnedPorts() for the filestore pod incorrectly includes port 9105, " +
			"owned by ovnkube-node, not the filestore controller (see issue #85)")
	}
	if !owned[9212] {
		t.Error("GetOwnedPorts() for the filestore pod should still include its own port 9212")
	}
}

func TestGetListenInfo(t *testing.T) {
	t.Parallel()

	c := newTestClient()
	c.listenInfoMap["10.0.0.1"] = map[int]ListenInfo{
		443: {Port: 443, ListenAddress: "0.0.0.0", ProcessName: "nginx"},
	}

	info, ok := c.GetListenInfo("10.0.0.1", 443)
	if !ok {
		t.Fatal("expected ok=true for known port")
	}
	if info.ListenAddress != "0.0.0.0" {
		t.Errorf("ListenAddress = %q, want %q", info.ListenAddress, "0.0.0.0")
	}

	_, ok = c.GetListenInfo("10.0.0.1", 9999)
	if ok {
		t.Error("expected ok=false for unknown port")
	}

	_, ok = c.GetListenInfo("10.0.0.2", 443)
	if ok {
		t.Error("expected ok=false for unknown IP")
	}
}

func TestGetProcessName(t *testing.T) {
	t.Parallel()

	c := newTestClient()
	c.processNameMap["10.0.0.1"] = map[int]string{
		443: "nginx",
	}

	name, ok := c.GetProcessName("10.0.0.1", 443)
	if !ok || name != "nginx" {
		t.Errorf("GetProcessName() = (%q, %v), want (%q, true)", name, ok, "nginx")
	}

	_, ok = c.GetProcessName("10.0.0.1", 9999)
	if ok {
		t.Error("expected ok=false for unknown port")
	}

	_, ok = c.GetProcessName("10.0.0.2", 443)
	if ok {
		t.Error("expected ok=false for unknown IP")
	}
}

func TestIsLocalhostAddr(t *testing.T) {
	tests := []struct {
		addr string
		want bool
	}{
		{"127.0.0.1", true},
		{"::1", true},
		{"localhost", true},
		{"0.0.0.0", false},
		{"::", false},
		{"*", false},
		{"10.0.0.1", false},
		{"", false},
	}

	for _, tt := range tests {
		got := isLocalhostAddr(tt.addr)
		if got != tt.want {
			t.Errorf("isLocalhostAddr(%q) = %v, want %v", tt.addr, got, tt.want)
		}
	}
}
