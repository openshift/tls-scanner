package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/openshift/tls-scanner/internal/k8s"
	"github.com/openshift/tls-scanner/internal/timing"
)

type portScanResult struct {
	ip        string
	pod       k8s.PodInfo
	component *k8s.OpenshiftComponent
	result    PortResult
}

type DiscoveryResults struct {
	ScanJobs []ScanJob
	Skipped  []portScanResult
}

func (d DiscoveryResults) SkippedPorts() []SkippedPort {
	out := make([]SkippedPort, len(d.Skipped))
	for i, s := range d.Skipped {
		out[i] = SkippedPort{
			IP:           s.ip,
			Port:         s.result.Port,
			PodName:      s.pod.Name,
			PodNamespace: s.pod.Namespace,
			Status:       s.result.Status,
			Reason:       s.result.Reason,
		}
	}
	return out
}

func DiscoverTargets(pods []k8s.PodInfo, concurrentScans int, client *k8s.Client, sniHostname string) DiscoveryResults {
	defer timing.Timings.Track("discoverTargets", "")()

	discoveryWorkers := max(2, concurrentScans/2)

	progress := NewProgressTracker(len(pods))
	progress.Start(15 * time.Second)

	var scanJobs []ScanJob
	var skipped []portScanResult
	var mu sync.Mutex

	discoveryChan := make(chan k8s.PodInfo, len(pods))

	var discoveryWG sync.WaitGroup
	for w := 0; w < discoveryWorkers; w++ {
		discoveryWG.Add(1)
		go func(workerID int) {
			defer discoveryWG.Done()
			for pod := range discoveryChan {
				slog.Debug("discovery processing pod", "worker", workerID, "namespace", pod.Namespace, "pod", pod.Name)
				progress.PodDiscovered()

				var component *k8s.OpenshiftComponent
				if client != nil && pod.Pod != nil {
					var err error
					component, err = client.GetOpenshiftComponentFromPod(*pod.Pod)
					if err != nil {
						slog.Warn("failed to extract component from pod", "namespace", pod.Namespace, "pod", pod.Name, "error", err)
					}
				}

				specPorts, _ := k8s.DiscoverPortsFromPodSpec(pod.Pod)
				var procPorts []int
				procAvailable := false
				if client != nil {
					var err error
					procPorts, err = client.DiscoverPortsFromProc(pod)
					if err != nil {
						slog.Warn("/proc port discovery failed", "namespace", pod.Namespace, "pod", pod.Name, "error", err)
					} else {
						procAvailable = true
					}
				}

				var ownedPorts map[int]bool
				if client != nil && procAvailable {
					// Ownership must be resolved per-pod, not per-IP: hostNetwork
					// pods share the node's IP, so an IP-keyed lookup would leak
					// ports legitimately owned by other hostNetwork pods on the
					// same node into this pod's scan target list (see issue #85).
					ownedPorts = client.GetOwnedPorts(pod)
				}

				// ownedPorts == nil means /proc discovery never ran for this pod, so
				// there is nothing to filter by. An empty-but-non-nil ownedPorts is a
				// valid discovery result (no port resolved to this pod's own PID
				// namespace) and must still be filtered down to secondary-container
				// spec ports, if any — it is not evidence that discovery failed.
				if pod.Pod.Spec.HostNetwork && ownedPorts != nil && len(procPorts) > 0 {
					var secondarySpecPorts []int
					if len(pod.Containers) > 1 {
						secondarySpecPorts = k8s.DiscoverPortsFromSecondaryContainers(pod.Pod, pod.Containers[0])
					}
					procPorts = filterByProcessPorts(ownedPorts, procPorts, secondarySpecPorts)
				}

				// When /proc data is available use it as the ground truth — only
				// ports with an active listener are included. Fall back to
				// spec-declared ports only when proc discovery is unavailable or
				// failed, to avoid false positives from containerPorts that are
				// declared but never actually bound.
				var openPorts []int
				if procAvailable {
					openPorts = procPorts
				} else {
					openPorts = specPorts
				}

				// Identify plaintext probe ports up front so we can skip them below.
				probePorts := k8s.GetPlaintextProbePorts(pod.Pod)

				slog.Debug("discovery result",
					"worker", workerID, "namespace", pod.Namespace, "pod", pod.Name,
					"hostNetwork", pod.Pod.Spec.HostNetwork, "specPorts", specPorts,
					"procPorts", procPorts, "openPorts", openPorts,
					"probePorts", probePorts, "portCount", len(openPorts))

				for _, ip := range pod.IPs {
					if len(openPorts) == 0 {
						progress.PortSkipped()
						mu.Lock()
						skipped = append(skipped, portScanResult{
							ip:        ip,
							pod:       pod,
							component: component,
							result: PortResult{
								Port:   0,
								Status: StatusNoPorts,
								Reason: "No listening TCP ports found (spec or /proc/net/tcp)",
							},
						})
						mu.Unlock()
						continue
					}

					for _, port := range openPorts {
						if client != nil {
							if isLocalhost, listenAddr := client.IsLocalhostOnly(ip, port); isLocalhost {
								slog.Debug("port bound to localhost only, skipping", "port", port, "ip", ip, "listenAddr", listenAddr)
								pr := PortResult{
									Port:          port,
									Protocol:      "tcp",
									State:         "localhost",
									Status:        StatusLocalhostOnly,
									Reason:        fmt.Sprintf("Bound to %s, not accessible from pod IP", listenAddr),
									ListenAddress: listenAddr,
								}
								if processName, ok := client.GetProcessName(ip, port); ok {
									pr.ProcessName = processName
									pr.ContainerName = strings.Join(pod.Containers, ",")
								}
								progress.PortSkipped()
								mu.Lock()
								skipped = append(skipped, portScanResult{
									ip: ip, pod: pod, component: component, result: pr,
								})
								mu.Unlock()
								continue
							}
						}

						if probePorts[port] {
							slog.Debug("plaintext health probe endpoint, skipping TLS scan", "port", port, "ip", ip)
							pr := PortResult{
								Port:     port,
								Protocol: "tcp",
								State:    "open",
								Status:   StatusProbePort,
								Reason:   "Port is used as a plaintext health probe endpoint (HTTP/TCP/gRPC), TLS not expected",
							}
							if client != nil {
								if processName, ok := client.GetProcessName(ip, port); ok {
									pr.ProcessName = processName
									pr.ContainerName = strings.Join(pod.Containers, ",")
								}
								if info, ok := client.GetListenInfo(ip, port); ok {
									pr.ListenAddress = info.ListenAddress
								}
							}
							progress.PortSkipped()
							mu.Lock()
							skipped = append(skipped, portScanResult{
								ip: ip, pod: pod, component: component, result: pr,
							})
							mu.Unlock()
							continue
						}

						progress.PortQueued()
						mu.Lock()
						scanJobs = append(scanJobs, ScanJob{IP: ip, Port: port, Pod: pod, Component: component, SNIHostname: sniHostname})
						mu.Unlock()
					}
				}
			}
		}(w + 1)
	}

	for _, pod := range pods {
		discoveryChan <- pod
	}
	close(discoveryChan)
	discoveryWG.Wait()
	progress.Stop()

	beforeDedup := len(scanJobs)
	scanJobs = deduplicateScanJobs(scanJobs)

	fmt.Printf("\n=== DISCOVERY COMPLETE: %d pods -> %d scan jobs (%d deduplicated), %d skipped ===\n\n",
		progress.discoveredPods.Load(), len(scanJobs), beforeDedup-len(scanJobs), progress.skippedPorts.Load())

	return DiscoveryResults{ScanJobs: scanJobs, Skipped: skipped}
}

func PerformClusterScan(pods []k8s.PodInfo, concurrentScans int, client *k8s.Client, policy *ComponentPolicy, timeouts ScanTimeouts, tlsProfileOverride *k8s.TLSSecurityProfile, starttlsPorts StarttlsPorts, sniHostname string) ScanResults {
	defer timing.Timings.Track("performClusterScan", "")()
	startTime := time.Now()

	totalIPs := 0
	for _, pod := range pods {
		totalIPs += len(pod.IPs)
	}

	fmt.Printf(`========================================
CLUSTER SCAN STARTING
========================================
Total Pods: %d
Total IPs: %d
MAX_PARALLEL (testssl): %d
========================================

`, len(pods), totalIPs, concurrentScans)

	var tlsConfig *k8s.TLSSecurityProfile
	if tlsProfileOverride != nil {
		tlsConfig = tlsProfileOverride
		if tlsConfig.APIServer != nil {
			slog.Info("using TLS security profile override", "type", tlsConfig.APIServer.Type)
		}
	} else if client != nil {
		if config, err := client.GetTLSSecurityProfile(); err != nil {
			slog.Warn("could not collect TLS security profiles", "error", err)
		} else {
			tlsConfig = config
		}
	}

	discovery := DiscoverTargets(pods, concurrentScans, client, sniHostname)

	batchResults := batchScan(discovery.ScanJobs, concurrentScans, client, tlsConfig, policy, timeouts, starttlsPorts)

	results := assembleResults(startTime, totalIPs, tlsConfig, discovery.Skipped, batchResults)

	duration := time.Since(startTime)
	fmt.Printf("\n========================================\n")
	fmt.Printf("CLUSTER SCAN COMPLETE!\n")
	fmt.Printf("========================================\n")
	fmt.Printf("Total IPs processed: %d\n", results.ScannedIPs)
	fmt.Printf("Total ports scanned: %d\n", len(batchResults))
	fmt.Printf("Total ports skipped: %d\n", len(discovery.Skipped))
	fmt.Printf("Total time: %v\n", duration)
	if len(batchResults) > 0 {
		fmt.Printf("Throughput: %.2f ports/min\n", float64(len(batchResults))/duration.Minutes())
	}
	fmt.Printf("========================================\n")

	return results
}

// Scan runs a batch testssl.sh scan on pre-built scan jobs.
// Used by --targets and single-host paths (no k8s discovery needed).
func Scan(jobs []ScanJob, concurrentScans int, client *k8s.Client, tlsConfig *k8s.TLSSecurityProfile, policy *ComponentPolicy, timeouts ScanTimeouts, starttlsPorts StarttlsPorts) ScanResults {
	defer timing.Timings.Track("scan", "")()
	startTime := time.Now()

	if len(jobs) == 0 {
		return ScanResults{Timestamp: startTime.Format(time.RFC3339)}
	}

	fmt.Printf("========================================\n")
	fmt.Printf("SCAN STARTING\n")
	fmt.Printf("========================================\n")
	fmt.Printf("Total targets: %d\n", len(jobs))
	fmt.Printf("MAX_PARALLEL: %d\n", concurrentScans)
	fmt.Printf("========================================\n\n")

	batchResults := batchScan(jobs, concurrentScans, client, tlsConfig, policy, timeouts, starttlsPorts)
	results := assembleResults(startTime, 0, tlsConfig, batchResults)

	duration := time.Since(startTime)
	fmt.Printf("\n========================================\n")
	fmt.Printf("SCAN COMPLETE!\n")
	fmt.Printf("========================================\n")
	fmt.Printf("Total IPs processed: %d\n", results.ScannedIPs)
	fmt.Printf("Total targets: %d\n", len(jobs))
	fmt.Printf("Total time: %v\n", duration)
	if results.ScannedIPs > 0 {
		fmt.Printf("Average time per host: %.2fs\n", duration.Seconds()/float64(results.ScannedIPs))
	}
	fmt.Printf("========================================\n")

	return results
}

func batchScan(jobs []ScanJob, concurrentScans int, client *k8s.Client, tlsConfig *k8s.TLSSecurityProfile, policy *ComponentPolicy, timeouts ScanTimeouts, starttlsPorts StarttlsPorts) []portScanResult {
	if len(jobs) == 0 {
		return nil
	}

	// Split jobs into direct-TLS and STARTTLS groups.
	// Explicit --starttls-ports mappings take priority; otherwise fall back to
	// process-name auto-detection (e.g. comm "postgres" → STARTTLS postgres).
	var directJobs []ScanJob
	starttlsGroups := make(map[string][]ScanJob)
	for _, job := range jobs {
		if proto := starttlsPorts[job.Port]; proto != "" {
			starttlsGroups[proto] = append(starttlsGroups[proto], job)
		} else if client != nil {
			if comm, ok := client.GetProcessName(job.IP, job.Port); ok {
				if proto := StarttlsProtoForProcess(comm); proto != "" {
					slog.Info("auto-detected STARTTLS protocol from process name", "ip", job.IP, "port", job.Port, "process", comm, "protocol", proto)
					starttlsGroups[proto] = append(starttlsGroups[proto], job)
					continue
				}
			}
			directJobs = append(directJobs, job)
		} else {
			directJobs = append(directJobs, job)
		}
	}

	var results []portScanResult
	if len(directJobs) > 0 {
		results = append(results, scanBatchGroup(directJobs, concurrentScans, "", client, tlsConfig, policy, timeouts)...)
	}
	for proto, protoJobs := range starttlsGroups {
		results = append(results, scanBatchGroup(protoJobs, concurrentScans, proto, client, tlsConfig, policy, timeouts)...)
	}

	return results
}

func scanBatchGroup(jobs []ScanJob, concurrentScans int, starttls string, client *k8s.Client, tlsConfig *k8s.TLSSecurityProfile, policy *ComponentPolicy, timeouts ScanTimeouts) []portScanResult {
	jobIndex := make(map[string]ScanJob, len(jobs))
	targets := make([]string, 0, len(jobs))
	for _, job := range jobs {
		key := targetKey(job.IP, strconv.Itoa(job.Port))
		jobIndex[key] = job
		targets = append(targets, targetLine(job))
	}

	targetsFile, err := writeTargetsFile(targets)
	if err != nil {
		slog.Error("failed to create targets file", "error", err)
		return nil
	}
	defer os.Remove(targetsFile)

	outputFile, err := os.CreateTemp("", "testssl-batch-*.json")
	if err != nil {
		slog.Error("failed to create output file", "error", err)
		return nil
	}
	outputFileName := outputFile.Name()
	outputFile.Close()
	defer os.Remove(outputFileName)

	label := "testssl.sh[batch]"
	if starttls != "" {
		label = fmt.Sprintf("testssl.sh[batch-starttls-%s]", starttls)
	}
	slog.Info("running batch scan", "label", label, "targets", len(targets), "maxParallel", concurrentScans)
	perTarget := time.Duration(timeouts.PerTargetSeconds) * time.Second
	timeout := perTarget*time.Duration(len(targets)) + 2*time.Minute
	slog.Debug("batch timeout set", "timeout", timeout)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	connectTimeoutStr := strconv.Itoa(timeouts.ConnectTimeout)
	args := []string{"-p", "-s", "-f", "-E",
		"--connect-timeout", connectTimeoutStr,
		"--openssl-timeout", connectTimeoutStr,
		"--file", targetsFile,
		"--jsonfile", outputFileName,
		"--warnings", "off",
		"--color", "0",
		"--parallel"}
	if starttls != "" {
		args = append(args, "--starttls", starttls)
	}
	cmd := exec.CommandContext(ctx, "testssl.sh", args...)
	cmd.Env = append(os.Environ(), fmt.Sprintf("MAX_PARALLEL=%d", concurrentScans))
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	stop := timing.Timings.Track(label, fmt.Sprintf("%d targets", len(targets)))
	cmdErr := cmd.Run()
	stop()

	if cmdErr != nil {
		if ctx.Err() == context.DeadlineExceeded {
			slog.Error("batch scan timed out, partial results may be available", "label", label, "timeout", timeout, "targets", len(targets))
		} else {
			slog.Warn("batch scan exited non-zero", "label", label, "error", cmdErr)
		}
	}

	jsonData, readErr := os.ReadFile(outputFileName)
	if readErr != nil || len(jsonData) == 0 {
		slog.Error("batch scan produced no output", "label", label, "error", readErr)
		return nil
	}

	grouped, groupErr := GroupTestSSLOutputByIPPort(jsonData)
	if groupErr != nil {
		slog.Error("grouping testssl.sh output", "error", groupErr)
		return nil
	}

	var results []portScanResult

	for key, findings := range grouped {
		job, ok := jobIndex[key]
		if !ok {
			slog.Warn("testssl returned results for unknown target", "target", key)
			continue
		}
		delete(jobIndex, key)

		portData, _ := json.Marshal(findings)
		scanResult := ParseTestSSLOutput(portData, job.IP, strconv.Itoa(job.Port))

		portResult := PortResult{
			Port:             job.Port,
			Protocol:         "tcp",
			State:            "open",
			Service:          "ssl/tls",
			STARTTLSProtocol: starttls,
		}

		portResult.TlsVersions = ExtractTLSInfo(scanResult)
		portResult.TlsCiphers = ExtractCiphersFromTestSSL(portData)
		portResult.TlsKeyExchange = ExtractKeyExchangeFromTestSSL(portData)

		PopulatePQCFields(&portResult)

		// Fetch process/listen info before compliance so the policy can match on
		// process name in addition to namespace and port.
		var processName string
		if client != nil {
			if pn, ok := client.GetProcessName(job.IP, job.Port); ok {
				portResult.ProcessName = pn
				portResult.ContainerName = strings.Join(job.Pod.Containers, ",")
				processName = pn
			}
			if info, ok := client.GetListenInfo(job.IP, job.Port); ok {
				portResult.ListenAddress = info.ListenAddress
			}
		}

		var componentName string
		if job.Component != nil {
			componentName = job.Component.Component
		}

		if len(portResult.TlsVersions) > 0 || len(portResult.TlsCiphers) > 0 {
			portResult.Status = StatusOK
			portResult.Reason = "TLS scan successful"
			if tlsConfig != nil && policy != nil {
				componentType := policy.Resolve(job.Pod.Namespace, processName, componentName, job.Port)
				CheckCompliance(&portResult, tlsConfig, componentType)
			}
		} else {
			portResult.Status = StatusNoTLS
			portResult.Reason = "Port open but no TLS detected"
		}

		results = append(results, portScanResult{
			ip: job.IP, pod: job.Pod, component: job.Component, result: portResult,
		})
	}

	for key, job := range jobIndex {
		slog.Warn("no testssl results for target", "target", key)
		results = append(results, portScanResult{
			ip: job.IP, pod: job.Pod, component: job.Component,
			result: PortResult{
				Port:             job.Port,
				Protocol:         "tcp",
				State:            "open",
				Status:           StatusNoTLS,
				Reason:           "No TLS data returned from batch scan",
				STARTTLSProtocol: starttls,
			},
		})
	}

	return results
}

func assembleResults(startTime time.Time, totalIPs int, tlsConfig *k8s.TLSSecurityProfile, portResults ...[]portScanResult) ScanResults {
	ipResultMap := make(map[string]*IPResult)
	uniqueIPs := make(map[string]bool)

	for _, batch := range portResults {
		for _, r := range batch {
			// Pods sharing the same hosted network have the same IP.
			// Include the pod namespace and name to make the key unique
			// for ports. Use bracket notation to avoid ambiguity with IPv6
			// addresses (which contain colons).
			key := fmt.Sprintf("[%s]:%s/%s", r.ip, r.pod.Namespace, r.pod.Name)

			ir, ok := ipResultMap[key]
			if !ok {
				ir = &IPResult{
					IP:                 r.ip,
					OpenshiftComponent: r.component,
					Status:             "scanned",
					OpenPorts:          []int{},
					PortResults:        []PortResult{},
				}
				if r.pod.Name != "" {
					pod := r.pod
					ir.Pod = &pod
				}
				ipResultMap[key] = ir
			}
			if r.result.Port > 0 {
				found := false
				for _, p := range ir.OpenPorts {
					if p == r.result.Port {
						found = true
						break
					}
				}
				if !found {
					ir.OpenPorts = append(ir.OpenPorts, r.result.Port)
				}
			}
			ir.PortResults = append(ir.PortResults, r.result)
			uniqueIPs[r.ip] = true
		}
	}

	if totalIPs == 0 {
		totalIPs = len(ipResultMap)
	}

	results := ScanResults{
		Timestamp:         startTime.Format(time.RFC3339),
		TotalIPs:          totalIPs,
		IPResults:         make([]IPResult, 0, len(ipResultMap)),
		TLSSecurityConfig: tlsConfig,
		ScannedIPs:        len(uniqueIPs),
	}
	for _, ir := range ipResultMap {
		results.IPResults = append(results.IPResults, *ir)
	}

	return results
}

func LimitPodsToIPCount(pods []k8s.PodInfo, maxIPs int) []k8s.PodInfo {
	if maxIPs <= 0 {
		return pods
	}

	var limitedPods []k8s.PodInfo
	currentIPCount := 0

	for _, pod := range pods {
		if currentIPCount >= maxIPs {
			break
		}

		if currentIPCount+len(pod.IPs) > maxIPs {
			remainingIPs := maxIPs - currentIPCount
			limitedPod := pod
			limitedPod.IPs = pod.IPs[:remainingIPs]
			limitedPods = append(limitedPods, limitedPod)
			break
		}

		limitedPods = append(limitedPods, pod)
		currentIPCount += len(pod.IPs)
	}

	return limitedPods
}

// filterByProcessPorts keeps procPorts owned by this pod: either resolved via
// /proc inode resolution scoped to this pod's own PID namespace (ownedPorts),
// or declared in a secondary container's pod spec (specPorts).
//
// ownedPorts must come from a per-pod-scoped source (e.g. Client.GetOwnedPorts)
// rather than a cache shared across pods on the same IP, otherwise ports
// legitimately owned by a different hostNetwork pod on the same node can leak
// through as false positives (see issue #85).
func filterByProcessPorts(ownedPorts map[int]bool, procPorts []int, specPorts []int) []int {
	owned := make(map[int]bool, len(ownedPorts)+len(specPorts))
	for port := range ownedPorts {
		owned[port] = true
	}
	for _, p := range specPorts {
		owned[p] = true
	}
	var filtered []int
	for _, p := range procPorts {
		if owned[p] {
			filtered = append(filtered, p)
		}
	}
	return filtered
}

func deduplicateScanJobs(jobs []ScanJob) []ScanJob {
	keyIndex := make(map[string]int)
	var unique []ScanJob

	specPortsCache := make(map[string]map[int]bool)
	getSpecPorts := func(pod k8s.PodInfo) map[int]bool {
		key := pod.Namespace + "/" + pod.Name
		if ports, ok := specPortsCache[key]; ok {
			return ports
		}
		portList, _ := k8s.DiscoverPortsFromPodSpec(pod.Pod)
		portSet := make(map[int]bool, len(portList))
		for _, p := range portList {
			portSet[p] = true
		}
		specPortsCache[key] = portSet
		return portSet
	}

	for _, job := range jobs {
		key := targetKey(job.IP, strconv.Itoa(job.Port))
		idx, exists := keyIndex[key]

		if !exists {
			keyIndex[key] = len(unique)
			unique = append(unique, job)
			continue
		}

		// Select the first pod that specifies the port in its spec (if there's any)
		// to find the owning pod. Pods sharing the same host network see the same
		// list of ports which makes the ownership ambiguous.
		jobDeclares := getSpecPorts(job.Pod)[job.Port]
		existingDeclares := getSpecPorts(unique[idx].Pod)[unique[idx].Port]

		if jobDeclares && existingDeclares {
			slog.Debug("duplicate target: both pods declare port, keeping first",
				"target", key,
				"kept", unique[idx].Pod.Namespace+"/"+unique[idx].Pod.Name,
				"skipped", job.Pod.Namespace+"/"+job.Pod.Name,
				"port", job.Port)
		} else if jobDeclares && !existingDeclares {
			slog.Debug("duplicate target: replacing with pod that declares port",
				"target", key,
				"replaced", unique[idx].Pod.Namespace+"/"+unique[idx].Pod.Name,
				"with", job.Pod.Namespace+"/"+job.Pod.Name,
				"port", job.Port)
			unique[idx] = job
		}
	}

	return unique
}

func writeTargetsFile(targets []string) (string, error) {
	f, err := os.CreateTemp("", "testssl-targets-*.txt")
	if err != nil {
		return "", err
	}
	for _, t := range targets {
		fmt.Fprintln(f, t)
	}
	f.Close()
	return f.Name(), nil
}

func targetKey(host, port string) string {
	return net.JoinHostPort(normalizeTargetHost(host), port)
}

// targetLine builds the string written to testssl.sh's --file batch input for
// job. Each line of that file is passed through as additional testssl.sh
// arguments (see run_mass_testing/create_mass_testing_cmdline upstream), so a
// line may carry flags in addition to the host:port target. When
// job.SNIHostname is set, the line connects to job.IP via --ip= while sending
// SNIHostname as the TLS servername, instead of sending job.IP as SNI.
func targetLine(job ScanJob) string {
	key := targetKey(job.IP, strconv.Itoa(job.Port))
	if job.SNIHostname == "" {
		return key
	}
	return fmt.Sprintf("--ip=%s %s", normalizeTargetHost(job.IP), targetKey(job.SNIHostname, strconv.Itoa(job.Port)))
}

func normalizeTargetHost(host string) string {
	host = strings.TrimSpace(host)
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") && len(host) >= 2 {
		return host[1 : len(host)-1]
	}
	return host
}
