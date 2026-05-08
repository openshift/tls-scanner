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

func DiscoverTargets(pods []k8s.PodInfo, concurrentScans int, client *k8s.Client) DiscoveryResults {
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
					component, _ = client.GetOpenshiftComponentFromPod(*pod.Pod)
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

			var processMap map[string]map[int]string
			if client != nil && len(pod.Containers) > 0 {
				processMap = client.GetAndCachePodProcesses(pod)
			}

			if pod.Pod.Spec.HostNetwork && processMap != nil && len(procPorts) > 0 {
				procPorts = filterByProcessPorts(processMap, procPorts)
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
						scanJobs = append(scanJobs, ScanJob{IP: ip, Port: port, Pod: pod, Component: component})
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

func PerformClusterScan(pods []k8s.PodInfo, concurrentScans int, client *k8s.Client, policy *ComponentPolicy) ScanResults {
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
	if client != nil {
		if config, err := client.GetTLSSecurityProfile(); err != nil {
			slog.Warn("could not collect TLS security profiles", "error", err)
		} else {
			tlsConfig = config
		}
	}

	discovery := DiscoverTargets(pods, concurrentScans, client)

	batchResults := batchScan(discovery.ScanJobs, concurrentScans, client, tlsConfig, policy)

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
func Scan(jobs []ScanJob, concurrentScans int, client *k8s.Client, tlsConfig *k8s.TLSSecurityProfile, policy *ComponentPolicy) ScanResults {
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

	batchResults := batchScan(jobs, concurrentScans, client, tlsConfig, policy)
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

func batchScan(jobs []ScanJob, concurrentScans int, client *k8s.Client, tlsConfig *k8s.TLSSecurityProfile, policy *ComponentPolicy) []portScanResult {
	if len(jobs) == 0 {
		return nil
	}

	jobIndex := make(map[string]ScanJob, len(jobs))
	targets := make([]string, 0, len(jobs))
	for _, job := range jobs {
		key := targetKey(job.IP, strconv.Itoa(job.Port))
		jobIndex[key] = job
		targets = append(targets, key)
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

	slog.Info("running testssl.sh batch scan", "targets", len(targets), "maxParallel", concurrentScans)
	timeout := time.Duration(len(targets)*90+120) * time.Second
	slog.Debug("batch timeout set", "timeout", timeout)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "testssl.sh", "-p", "-s", "-f", "-E",
		"--connect-timeout", "5",
		"--openssl-timeout", "5",
		"--file", targetsFile,
		"--jsonfile", outputFileName,
		"--warnings", "off",
		"--color", "0",
		"--parallel")
	cmd.Env = append(os.Environ(), fmt.Sprintf("MAX_PARALLEL=%d", concurrentScans))
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	stop := timing.Timings.Track("testssl.sh[batch]", fmt.Sprintf("%d targets", len(targets)))
	cmdErr := cmd.Run()
	stop()

	if cmdErr != nil {
		if ctx.Err() == context.DeadlineExceeded {
			slog.Error("testssl.sh batch timed out, partial results may be available", "timeout", timeout, "targets", len(targets))
		} else {
			slog.Warn("testssl.sh batch exited non-zero", "error", cmdErr)
		}
	}

	jsonData, readErr := os.ReadFile(outputFileName)
	if readErr != nil || len(jsonData) == 0 {
		slog.Error("testssl.sh batch produced no output", "error", readErr)
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
			Port:     job.Port,
			Protocol: "tcp",
			State:    "open",
			Service:  "ssl/tls",
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
				Port:     job.Port,
				Protocol: "tcp",
				State:    "open",
				Status:   StatusNoTLS,
				Reason:   "No TLS data returned from batch scan",
			},
		})
	}

	return results
}

func assembleResults(startTime time.Time, totalIPs int, tlsConfig *k8s.TLSSecurityProfile, portResults ...[]portScanResult) ScanResults {
	ipResultMap := make(map[string]*IPResult)

	for _, batch := range portResults {
		for _, r := range batch {
			ir, ok := ipResultMap[r.ip]
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
				ipResultMap[r.ip] = ir
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
	}
	for _, ir := range ipResultMap {
		results.IPResults = append(results.IPResults, *ir)
		results.ScannedIPs++
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

func filterByProcessPorts(processMap map[string]map[int]string, procPorts []int) []int {
	owned := make(map[int]bool)
	for _, portMap := range processMap {
		for port := range portMap {
			owned[port] = true
		}
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
	seen := make(map[string]bool, len(jobs))
	var unique []ScanJob
	for _, job := range jobs {
		key := targetKey(job.IP, strconv.Itoa(job.Port))
		if seen[key] {
			continue
		}
		seen[key] = true
		unique = append(unique, job)
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

func normalizeTargetHost(host string) string {
	host = strings.TrimSpace(host)
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") && len(host) >= 2 {
		return host[1 : len(host)-1]
	}
	return host
}
