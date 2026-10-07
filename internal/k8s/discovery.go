package k8s

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/remotecommand"
)

const (
	procStateListen    = "0A"
	podExecTimeout     = 30 * time.Second
	inodeMapSentinel   = "__INODE_MAP__"
	procDiscoveryShell = `cat /proc/net/tcp /proc/net/tcp6 2>/dev/null; printf '\n` + inodeMapSentinel + `\n'; for p in /proc/[0-9]*; do [ -f "$p/comm" ] || continue; comm=$(cat "$p/comm" 2>/dev/null) || continue; for fd in "$p"/fd/*; do target=$(readlink "$fd" 2>/dev/null) || continue; case "$target" in socket:\[*) inode=${target#socket:[}; inode=${inode%]}; echo "$inode $comm";; esac; done; done`
)

func DiscoverPortsFromPodSpec(pod *corev1.Pod) ([]int, error) {
	slog.Debug("discovering ports from API server", "namespace", pod.Namespace, "pod", pod.Name)

	var ports []int
	for _, container := range pod.Spec.Containers {
		for _, port := range container.Ports {
			if port.Protocol == corev1.ProtocolTCP {
				ports = append(ports, int(port.ContainerPort))
			}
		}
	}

	for _, container := range pod.Spec.InitContainers {
		for _, port := range container.Ports {
			if port.Protocol == corev1.ProtocolTCP {
				ports = append(ports, int(port.ContainerPort))
			}
		}
	}

	if len(ports) == 0 {
		slog.Debug("no declared TCP ports found", "namespace", pod.Namespace, "pod", pod.Name)
	} else {
		slog.Debug("declared TCP ports found", "namespace", pod.Namespace, "pod", pod.Name, "count", len(ports), "ports", ports)
	}

	return ports, nil
}

// DiscoverPortsFromSecondaryContainers returns TCP ports from containers other than execContainer.
//
// TODO(refactor): extract shared tcpPortsFromContainers helper; drop never-used error return from DiscoverPortsFromPodSpec
func DiscoverPortsFromSecondaryContainers(pod *corev1.Pod, execContainer string) []int {
	var ports []int
	for _, container := range pod.Spec.Containers {
		if container.Name == execContainer {
			continue
		}
		for _, port := range container.Ports {
			if port.Protocol == corev1.ProtocolTCP {
				ports = append(ports, int(port.ContainerPort))
			}
		}
	}
	return ports
}

func (c *Client) DiscoverPortsFromProc(pod PodInfo) ([]int, error) {
	if len(pod.Containers) == 0 {
		return nil, fmt.Errorf("pod %s/%s has no containers", pod.Namespace, pod.Name)
	}

	// /proc/net/tcp is part of the network namespace, which is shared across
	// ALL containers in a pod. Reading from Containers[0] gives complete
	// visibility into every listening socket. Process names are resolved via
	// socket inodes visible in Containers[0]'s PID namespace.
	command := []string{"/bin/sh", "-c", procDiscoveryShell}
	containerName := pod.Containers[0]

	req := c.clientset.CoreV1().RESTClient().Post().
		Resource("pods").
		Name(pod.Name).
		Namespace(pod.Namespace).
		SubResource("exec")

	req.VersionedParams(&corev1.PodExecOptions{
		Container: containerName,
		Command:   command,
		Stdin:     false,
		Stdout:    true,
		Stderr:    true,
		TTY:       false,
	}, scheme.ParameterCodec)

	executor, err := remotecommand.NewSPDYExecutor(c.restCfg, "POST", req.URL())
	if err != nil {
		return nil, fmt.Errorf("failed to create executor for pod %s/%s: %w", pod.Namespace, pod.Name, err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), podExecTimeout)
	defer cancel()

	var stdout, stderr bytes.Buffer
	err = executor.StreamWithContext(ctx, remotecommand.StreamOptions{
		Stdout: &stdout,
		Stderr: &stderr,
	})
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return nil, fmt.Errorf("/proc/net/tcp exec TIMED OUT in pod %s/%s (30s)", pod.Namespace, pod.Name)
		}
		return nil, fmt.Errorf("exec cat /proc/net/tcp in pod %s/%s failed: %w", pod.Namespace, pod.Name, err)
	}

	tcpPart, inodePart := splitMergedProcOutput(stdout.String())
	entries := ParseProcNetTCPWithAddrs(tcpPart)
	inodeComm := ParseInodeCommMap(inodePart)

	if len(entries) > 0 {
		c.cacheProcListenInfo(pod, entries, inodeComm)
	}

	ports := make([]int, 0, len(entries))
	for port := range entries {
		ports = append(ports, port)
	}
	slog.Debug("discovered listening ports from /proc/net/tcp", "namespace", pod.Namespace, "pod", pod.Name, "count", len(ports), "ports", ports)
	return ports, nil
}

// TODO(refactor): move ParseProcNetTCPWithAddrs + decodeProcNetAddr to internal/netdiscovery

func splitMergedProcOutput(output string) (tcpPart, inodePart string) {
	idx := strings.Index(output, inodeMapSentinel)
	if idx < 0 {
		return output, ""
	}
	tcpPart = output[:idx]
	inodePart = strings.TrimPrefix(output[idx+len(inodeMapSentinel):], "\n")
	return tcpPart, inodePart
}

// ParseInodeCommMap parses lines of "inode comm" emitted after inodeMapSentinel.
func ParseInodeCommMap(output string) map[uint64]string {
	result := make(map[uint64]string)
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		inode, err := strconv.ParseUint(fields[0], 10, 64)
		if err != nil {
			continue
		}
		result[inode] = fields[1]
	}
	return result
}

// ParseProcNetTCPWithAddrs parses /proc/net/tcp (and /proc/net/tcp6) output and
// returns a map of port → listen entry for every socket in the LISTEN state.
//
// When the same port appears on multiple rows (e.g. SO_REUSEPORT with mixed
// bindings, or the same port in both /proc/net/tcp and /proc/net/tcp6), a
// reachable address (0.0.0.0, ::, or any non-loopback) always takes precedence
// over a loopback address. This prevents a false LOCALHOST_ONLY classification
// when a port is bound to both 127.0.0.1 and 0.0.0.0.
//
// Addresses are returned as standard Go strings: "127.0.0.1", "0.0.0.0", "::1", "::", etc.
func ParseProcNetTCPWithAddrs(output string) map[int]ProcListenEntry {
	result := make(map[int]ProcListenEntry)

	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		if fields[3] != procStateListen {
			continue
		}

		parts := strings.SplitN(fields[1], ":", 2)
		if len(parts) != 2 {
			continue
		}

		port64, err := strconv.ParseInt(parts[1], 16, 32)
		if err != nil {
			continue
		}
		port := int(port64)
		addr := decodeProcNetAddr(parts[0])

		var inode uint64
		if len(fields) >= 10 {
			inode, _ = strconv.ParseUint(fields[9], 10, 64)
		}

		entry := ProcListenEntry{Addr: addr, Inode: inode}
		existing, seen := result[port]
		if !seen {
			result[port] = entry
		} else if isLocalhostAddr(existing.Addr) && !isLocalhostAddr(addr) {
			// A reachable binding overrides a previously recorded loopback one.
			// The inverse is never allowed: once we know a port is reachable we
			// do not let a later loopback row make it look localhost-only.
			result[port] = entry
		}
	}

	return result
}

// ParseProcNetTCP returns the list of listening port numbers.
// It is a thin wrapper around ParseProcNetTCPWithAddrs that discards addresses.
func ParseProcNetTCP(output string) []int {
	addrMap := ParseProcNetTCPWithAddrs(output)
	if len(addrMap) == 0 {
		return nil
	}
	ports := make([]int, 0, len(addrMap))
	for port := range addrMap {
		ports = append(ports, port)
	}
	return ports
}

// decodeProcNetAddr converts a hex local-address field from /proc/net/tcp or
// /proc/net/tcp6 into a human-readable IP string.
//
// IPv4 entries are 8 hex characters representing a little-endian uint32.
// IPv6 entries are 32 hex characters representing four consecutive little-endian uint32s.
func decodeProcNetAddr(hexAddr string) string {
	b, err := hex.DecodeString(hexAddr)
	if err != nil {
		return hexAddr
	}

	switch len(b) {
	case 4: // IPv4 — little-endian uint32
		return fmt.Sprintf("%d.%d.%d.%d", b[3], b[2], b[1], b[0])
	case 16: // IPv6 — four consecutive little-endian uint32s
		decoded := make([]byte, 16)
		for i := 0; i < 4; i++ {
			decoded[i*4+0] = b[i*4+3]
			decoded[i*4+1] = b[i*4+2]
			decoded[i*4+2] = b[i*4+1]
			decoded[i*4+3] = b[i*4+0]
		}
		return net.IP(decoded).String()
	default:
		return hexAddr
	}
}

// GetPlaintextProbePorts returns the set of port numbers that are referenced by
// any liveness, readiness, or startup probe that does NOT use TLS (i.e. HTTP,
// TCPSocket, or gRPC probes). Ports used by HTTPS probes are excluded so that
// they continue to be scanned normally.
//
// Port references that use named ports (e.g. "healthz") are resolved against
// each container's declared Ports list.
func GetPlaintextProbePorts(pod *corev1.Pod) map[int]bool {
	result := make(map[int]bool)

	allContainers := append(pod.Spec.Containers, pod.Spec.InitContainers...)
	for _, container := range allContainers {
		namedPorts := buildNamedPortMap(container.Ports)

		for _, probe := range []*corev1.Probe{
			container.LivenessProbe,
			container.ReadinessProbe,
			container.StartupProbe,
		} {
			if probe == nil {
				continue
			}
			switch {
			case probe.HTTPGet != nil:
				if probe.HTTPGet.Scheme == corev1.URISchemeHTTPS {
					// HTTPS probe — TLS is explicitly in use; keep scanning this port.
					continue
				}
				if port := resolveProbePort(probe.HTTPGet.Port, namedPorts); port > 0 {
					result[port] = true
				}
			case probe.TCPSocket != nil:
				if port := resolveProbePort(probe.TCPSocket.Port, namedPorts); port > 0 {
					result[port] = true
				}
			case probe.GRPC != nil:
				result[int(probe.GRPC.Port)] = true
			}
		}
	}

	return result
}

// buildNamedPortMap returns a name → port number map from a container's port list.
func buildNamedPortMap(ports []corev1.ContainerPort) map[string]int {
	m := make(map[string]int, len(ports))
	for _, p := range ports {
		if p.Name != "" {
			m[p.Name] = int(p.ContainerPort)
		}
	}
	return m
}

// resolveProbePort resolves an IntOrString probe port to its integer value.
// Named ports are looked up in namedPorts. Returns 0 if the name is not found.
func resolveProbePort(port intstr.IntOrString, namedPorts map[string]int) int {
	if port.Type == intstr.Int {
		return int(port.IntVal)
	}
	return namedPorts[port.StrVal]
}

func UnionPorts(a, b []int) []int {
	seen := make(map[int]struct{}, len(a)+len(b))
	var result []int
	for _, p := range a {
		if _, ok := seen[p]; !ok {
			seen[p] = struct{}{}
			result = append(result, p)
		}
	}
	for _, p := range b {
		if _, ok := seen[p]; !ok {
			seen[p] = struct{}{}
			result = append(result, p)
		}
	}
	return result
}
