package k8s

import (
	"reflect"
	"sort"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

func TestParseProcNetTCPWithAddrs(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  map[int]ProcListenEntry
	}{
		{
			name: "ipv4 localhost and wildcard",
			input: `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:2438 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1 1 0000000000000000 100 0 0 10 0
   1: 00000000:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 2 1 0000000000000000 100 0 0 10 0`,
			want: map[int]ProcListenEntry{
				9272: {Addr: "127.0.0.1", Inode: 1},
				8080: {Addr: "0.0.0.0", Inode: 2},
			},
		},
		{
			name: "ipv6 localhost",
			input: `  sl  local_address                         remote_address                        st
   0: 00000000000000000000000001000000:2710 00000000000000000000000000000000:0000 0A`,
			want: map[int]ProcListenEntry{10000: {Addr: "::1"}},
		},
		{
			name: "ipv6 wildcard",
			input: `  sl  local_address                         remote_address                        st
   0: 00000000000000000000000000000000:01BB 00000000000000000000000000000000:0000 0A`,
			want: map[int]ProcListenEntry{443: {Addr: "::"}},
		},
		{
			name: "wildcard before localhost — wildcard wins",
			input: `  sl  local_address rem_address   st
   0: 00000000:01BB 00000000:0000 0A
   1: 0100007F:01BB 00000000:0000 0A`,
			want: map[int]ProcListenEntry{443: {Addr: "0.0.0.0"}},
		},
		{
			name: "localhost before wildcard — wildcard still wins",
			input: `  sl  local_address rem_address   st
   0: 0100007F:01BB 00000000:0000 0A
   1: 00000000:01BB 00000000:0000 0A`,
			want: map[int]ProcListenEntry{443: {Addr: "0.0.0.0"}},
		},
		{
			name: "two localhost rows — stays localhost",
			input: `  sl  local_address rem_address   st
   0: 0100007F:1F90 00000000:0000 0A
   1: 0100007F:1F90 00000000:0000 0A`,
			want: map[int]ProcListenEntry{8080: {Addr: "127.0.0.1"}},
		},
		{
			name: "non-listen state skipped",
			input: `  sl  local_address rem_address   st
   0: 0100007F:C350 AC100164:01BB 01
   1: 00000000:01BB 00000000:0000 0A`,
			want: map[int]ProcListenEntry{443: {Addr: "0.0.0.0"}},
		},
		{
			name:  "empty input",
			input: "",
			want:  map[int]ProcListenEntry{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ParseProcNetTCPWithAddrs(tt.input)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseProcNetTCPWithAddrs() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseInodeCommMap(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  map[uint64]string
	}{
		{
			name:  "single mapping",
			input: "12345 nginx\n",
			want:  map[uint64]string{12345: "nginx"},
		},
		{
			name:  "multiple mappings",
			input: "1 kubelet\n2 crio\n",
			want:  map[uint64]string{1: "kubelet", 2: "crio"},
		},
		{
			name:  "skips malformed lines",
			input: "bad\n12345 nginx\n",
			want:  map[uint64]string{12345: "nginx"},
		},
		{
			name:  "empty",
			input: "",
			want:  map[uint64]string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ParseInodeCommMap(tt.input)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseInodeCommMap() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSplitMergedProcOutput(t *testing.T) {
	tcp := "  sl  local_address rem_address   st\n   0: 00000000:01BB 00000000:0000 0A\n"
	inode := "12345 nginx\n"
	merged := tcp + "__INODE_MAP__\n" + inode

	gotTCP, gotInode := splitMergedProcOutput(merged)
	if gotTCP != tcp {
		t.Errorf("tcp part = %q, want %q", gotTCP, tcp)
	}
	if gotInode != inode {
		t.Errorf("inode part = %q, want %q", gotInode, inode)
	}

	gotTCP, gotInode = splitMergedProcOutput(tcp)
	if gotTCP != tcp || gotInode != "" {
		t.Errorf("without sentinel: tcp=%q inode=%q", gotTCP, gotInode)
	}
}

func TestDecodeProcNetAddr(t *testing.T) {
	tests := []struct {
		hex  string
		want string
	}{
		{"0100007F", "127.0.0.1"},
		{"00000000", "0.0.0.0"},
		{"0101A8C0", "192.168.1.1"},
		{"00000000000000000000000001000000", "::1"},
		{"00000000000000000000000000000000", "::"},
		{"invalid!", "invalid!"},
	}

	for _, tt := range tests {
		t.Run(tt.hex, func(t *testing.T) {
			got := decodeProcNetAddr(tt.hex)
			if got != tt.want {
				t.Errorf("decodeProcNetAddr(%q) = %q, want %q", tt.hex, got, tt.want)
			}
		})
	}
}

func TestParseProcNetTCP(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  []int
	}{
		{
			name: "standard ipv4 listeners",
			input: `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:01BB 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0
   1: 00000000:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12346 1 0000000000000000 100 0 0 10 0
   2: 0100007F:2710 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12347 1 0000000000000000 100 0 0 10 0`,
			want: []int{443, 8080, 10000},
		},
		{
			name: "mixed listen and established",
			input: `  sl  local_address rem_address   st
   0: 00000000:01BB 00000000:0000 0A
   1: 0100007F:C350 AC100164:01BB 01
   2: 00000000:1F90 00000000:0000 0A`,
			want: []int{443, 8080},
		},
		{
			name:  "empty input",
			input: "",
			want:  nil,
		},
		{
			name:  "header only",
			input: `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode`,
			want:  nil,
		},
		{
			name: "no listeners",
			input: `  sl  local_address rem_address   st
   0: 0100007F:C350 AC100164:01BB 01
   1: 0100007F:C351 AC100164:01BB 06`,
			want: nil,
		},
		{
			name: "ipv6 listeners",
			input: `  sl  local_address                         remote_address                        st
   0: 00000000000000000000000000000000:1F90 00000000000000000000000000000000:0000 0A
   1: 00000000000000000000000001000000:0050 00000000000000000000000000000000:0000 0A`,
			want: []int{8080, 80},
		},
		{
			name: "duplicate ports deduplicated",
			input: `  sl  local_address rem_address   st
   0: 00000000:01BB 00000000:0000 0A
   1: 0100007F:01BB 00000000:0000 0A`,
			want: []int{443},
		},
		{
			name: "malformed lines skipped",
			input: `  sl  local_address rem_address   st
   0: 00000000:01BB 00000000:0000 0A
   garbage line
   1: badformat 0A
   2: 00000000:0050 00000000:0000 0A`,
			want: []int{443, 80},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ParseProcNetTCP(tt.input)
			sort.Ints(got)
			sort.Ints(tt.want)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseProcNetTCP() = %v, want %v", got, tt.want)
			}
		})
	}
}
func TestDiscoverPortsFromPodSpec(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		pod  *corev1.Pod
		want []int
	}{
		{
			name: "TCP ports from containers",
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: "ns"},
				Spec: corev1.PodSpec{Containers: []corev1.Container{{
					Name: "c",
					Ports: []corev1.ContainerPort{
						{ContainerPort: 443, Protocol: corev1.ProtocolTCP},
						{ContainerPort: 8443, Protocol: corev1.ProtocolTCP},
					},
				}}},
			},
			want: []int{443, 8443},
		},
		{
			name: "UDP ports excluded",
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: "ns"},
				Spec: corev1.PodSpec{Containers: []corev1.Container{{
					Name: "c",
					Ports: []corev1.ContainerPort{
						{ContainerPort: 443, Protocol: corev1.ProtocolTCP},
						{ContainerPort: 53, Protocol: corev1.ProtocolUDP},
					},
				}}},
			},
			want: []int{443},
		},
		{
			name: "init container ports included",
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: "ns"},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{{
						Name:  "main",
						Ports: []corev1.ContainerPort{{ContainerPort: 443, Protocol: corev1.ProtocolTCP}},
					}},
					InitContainers: []corev1.Container{{
						Name:  "init",
						Ports: []corev1.ContainerPort{{ContainerPort: 9090, Protocol: corev1.ProtocolTCP}},
					}},
				},
			},
			want: []int{443, 9090},
		},
		{
			name: "no ports",
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: "ns"},
				Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "c"}}},
			},
			want: nil,
		},
		{
			name: "multiple containers",
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: "ns"},
				Spec: corev1.PodSpec{Containers: []corev1.Container{
					{Name: "c1", Ports: []corev1.ContainerPort{{ContainerPort: 443, Protocol: corev1.ProtocolTCP}}},
					{Name: "c2", Ports: []corev1.ContainerPort{{ContainerPort: 8443, Protocol: corev1.ProtocolTCP}}},
				}},
			},
			want: []int{443, 8443},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := DiscoverPortsFromPodSpec(tt.pod)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			sort.Ints(got)
			sort.Ints(tt.want)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("DiscoverPortsFromPodSpec() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDiscoverPortsFromSecondaryContainers(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		pod           *corev1.Pod
		execContainer string
		want          []int
	}{
		{
			name: "single container returns nothing",
			pod: &corev1.Pod{
				Spec: corev1.PodSpec{Containers: []corev1.Container{
					{Name: "main", Ports: []corev1.ContainerPort{{ContainerPort: 443, Protocol: corev1.ProtocolTCP}}},
				}},
			},
			execContainer: "main",
			want:          nil,
		},
		{
			name: "excludes exec container ports",
			pod: &corev1.Pod{
				Spec: corev1.PodSpec{Containers: []corev1.Container{
					{Name: "main", Ports: []corev1.ContainerPort{{ContainerPort: 443, Protocol: corev1.ProtocolTCP}}},
					{Name: "sidecar", Ports: []corev1.ContainerPort{{ContainerPort: 8443, Protocol: corev1.ProtocolTCP}}},
				}},
			},
			execContainer: "main",
			want:          []int{8443},
		},
		{
			name: "multiple secondary containers",
			pod: &corev1.Pod{
				Spec: corev1.PodSpec{Containers: []corev1.Container{
					{Name: "main", Ports: []corev1.ContainerPort{{ContainerPort: 443, Protocol: corev1.ProtocolTCP}}},
					{Name: "sidecar1", Ports: []corev1.ContainerPort{{ContainerPort: 8443, Protocol: corev1.ProtocolTCP}}},
					{Name: "sidecar2", Ports: []corev1.ContainerPort{{ContainerPort: 9090, Protocol: corev1.ProtocolTCP}}},
				}},
			},
			execContainer: "main",
			want:          []int{8443, 9090},
		},
		{
			name: "UDP ports excluded",
			pod: &corev1.Pod{
				Spec: corev1.PodSpec{Containers: []corev1.Container{
					{Name: "main", Ports: []corev1.ContainerPort{{ContainerPort: 443, Protocol: corev1.ProtocolTCP}}},
					{Name: "sidecar", Ports: []corev1.ContainerPort{
						{ContainerPort: 8443, Protocol: corev1.ProtocolTCP},
						{ContainerPort: 53, Protocol: corev1.ProtocolUDP},
					}},
				}},
			},
			execContainer: "main",
			want:          []int{8443},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := DiscoverPortsFromSecondaryContainers(tt.pod, tt.execContainer)
			sort.Ints(got)
			sort.Ints(tt.want)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("DiscoverPortsFromSecondaryContainers() = %v, want %v", got, tt.want)
			}
		})
	}
}

func intPort(n int) intstr.IntOrString      { return intstr.FromInt(n) }
func namedPort(s string) intstr.IntOrString { return intstr.FromString(s) }

func httpProbe(port intstr.IntOrString) *corev1.Probe {
	return &corev1.Probe{ProbeHandler: corev1.ProbeHandler{HTTPGet: &corev1.HTTPGetAction{Port: port, Scheme: corev1.URISchemeHTTP}}}
}

func httpsProbe(port intstr.IntOrString) *corev1.Probe {
	return &corev1.Probe{ProbeHandler: corev1.ProbeHandler{HTTPGet: &corev1.HTTPGetAction{Port: port, Scheme: corev1.URISchemeHTTPS}}}
}

func tcpProbe(port intstr.IntOrString) *corev1.Probe {
	return &corev1.Probe{ProbeHandler: corev1.ProbeHandler{TCPSocket: &corev1.TCPSocketAction{Port: port}}}
}

func grpcProbe(port int32) *corev1.Probe {
	return &corev1.Probe{ProbeHandler: corev1.ProbeHandler{GRPC: &corev1.GRPCAction{Port: port}}}
}

func TestGetPlaintextProbePorts(t *testing.T) {
	tests := []struct {
		name string
		pod  *corev1.Pod
		want map[int]bool
	}{
		{
			name: "http liveness probe by integer port",
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: "ns"},
				Spec: corev1.PodSpec{Containers: []corev1.Container{
					{Name: "c", LivenessProbe: httpProbe(intPort(10301))},
				}},
			},
			want: map[int]bool{10301: true},
		},
		{
			name: "http liveness probe via named port",
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: "ns"},
				Spec: corev1.PodSpec{Containers: []corev1.Container{
					{
						Name: "c",
						Ports: []corev1.ContainerPort{
							{Name: "healthz", ContainerPort: 10301, Protocol: corev1.ProtocolTCP},
						},
						LivenessProbe: httpProbe(namedPort("healthz")),
					},
				}},
			},
			want: map[int]bool{10301: true},
		},
		{
			name: "https liveness probe is NOT skipped",
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: "ns"},
				Spec: corev1.PodSpec{Containers: []corev1.Container{
					{Name: "c", LivenessProbe: httpsProbe(intPort(8443))},
				}},
			},
			want: map[int]bool{},
		},
		{
			name: "tcp readiness probe",
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: "ns"},
				Spec: corev1.PodSpec{Containers: []corev1.Container{
					{Name: "c", ReadinessProbe: tcpProbe(intPort(9090))},
				}},
			},
			want: map[int]bool{9090: true},
		},
		{
			name: "grpc startup probe",
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: "ns"},
				Spec: corev1.PodSpec{Containers: []corev1.Container{
					{Name: "c", StartupProbe: grpcProbe(5000)},
				}},
			},
			want: map[int]bool{5000: true},
		},
		{
			name: "all three probe types across multiple containers",
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: "ns"},
				Spec: corev1.PodSpec{Containers: []corev1.Container{
					{
						Name:           "c1",
						LivenessProbe:  httpProbe(intPort(8081)),
						ReadinessProbe: httpsProbe(intPort(8443)), // HTTPS — must not be skipped
					},
					{
						Name:         "c2",
						StartupProbe: tcpProbe(intPort(9000)),
					},
				}},
			},
			want: map[int]bool{8081: true, 9000: true},
		},
		{
			name: "named port not found returns zero — port excluded",
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: "ns"},
				Spec: corev1.PodSpec{Containers: []corev1.Container{
					{Name: "c", LivenessProbe: httpProbe(namedPort("missing"))},
				}},
			},
			want: map[int]bool{},
		},
		{
			name: "init container plaintext probe",
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: "ns"},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{Name: "main"},
					},
					InitContainers: []corev1.Container{
						{
							Name: "init",
							Ports: []corev1.ContainerPort{
								{Name: "healthz", ContainerPort: 9440, Protocol: corev1.ProtocolTCP},
							},
							LivenessProbe: httpProbe(namedPort("healthz")),
						},
					},
				},
			},
			want: map[int]bool{9440: true},
		},
		{
			name: "no probes",
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: "ns"},
				Spec: corev1.PodSpec{Containers: []corev1.Container{
					{Name: "c"},
				}},
			},
			want: map[int]bool{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GetPlaintextProbePorts(tt.pod)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetPlaintextProbePorts() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestUnionPorts(t *testing.T) {
	tests := []struct {
		name string
		a, b []int
		want []int
	}{
		{
			name: "disjoint",
			a:    []int{80, 443},
			b:    []int{8080, 9090},
			want: []int{80, 443, 8080, 9090},
		},
		{
			name: "overlapping",
			a:    []int{80, 443, 8080},
			b:    []int{443, 8080, 9090},
			want: []int{80, 443, 8080, 9090},
		},
		{
			name: "a empty",
			a:    nil,
			b:    []int{443},
			want: []int{443},
		},
		{
			name: "both empty",
			a:    nil,
			b:    nil,
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := UnionPorts(tt.a, tt.b)
			sort.Ints(got)
			sort.Ints(tt.want)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("UnionPorts() = %v, want %v", got, tt.want)
			}
		})
	}
}
