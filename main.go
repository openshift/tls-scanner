package main

import (
	"encoding/xml"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	v1 "k8s.io/api/core/v1"
)

func main() {
	var finalScanResults *ScanResults
	var isPQCCheck bool
	defer func() {
		if finalScanResults != nil {
			if isPQCCheck {
				if hasPQCComplianceFailures(*finalScanResults) {
					fmt.Println("\nPQC COMPLIANCE CHECK: FAILED")
					fmt.Println("One or more endpoints do not support TLS 1.3 + ML-KEM (x25519mlkem768 or mlkem768)")
					os.Exit(1)
				}
				fmt.Println("\nPQC COMPLIANCE CHECK: PASSED")
				fmt.Println("All endpoints support TLS 1.3 + ML-KEM")
			} else {
				if hasComplianceFailures(*finalScanResults) {
					os.Exit(1)
				}
			}
		}
	}()

	host := flag.String("host", "127.0.0.1", "The target host or IP address to scan")
	port := flag.String("port", "443", "The target port to scan")
	artifactDir := flag.String("artifact-dir", "/tmp", "Directory to save the artifacts to")
	jsonFile := flag.String("json-file", "", "Output results in JSON format to specified file in artifact-dir")
	csvFile := flag.String("csv-file", "", "Output results in CSV format to specified file in artifact-dir")
	junitFile := flag.String("junit-file", "", "Output results in JUnit XML format to specified file in artifact-dir")
	concurrentScans := flag.Int("j", 1, "Number of concurrent scans to run in parallel (speeds up large IP lists significantly!)")
	allPods := flag.Bool("all-pods", false, "Scan all pods in the current namespace (overrides --iplist and --host)")
	componentFilter := flag.String("component-filter", "", "Filter pods by a comma-separated list of component names (only used with --all-pods)")
	namespaceFilter := flag.String("namespace-filter", "", "Filter pods by a comma-separated list of namespaces (only used with --all-pods)")
	targets := flag.String("targets", "", "A comma-separated list of host:port targets to scan")
	limitIPs := flag.Int("limit-ips", 0, "Limit the number of IPs to scan for testing purposes (0 = no limit)")
	logFile := flag.String("log-file", "", "Redirect all log output to the specified file")
	pqcCheck := flag.Bool("pqc-check", false, "Quick check for TLS 1.3 and ML-KEM (post-quantum) support only")
	flag.Parse()

	if *logFile != "" {
		f, err := os.OpenFile(*logFile, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
		if err != nil {
			log.Fatalf("error opening file: %v", err)
		}
		defer f.Close()
		log.SetOutput(f)
		log.Printf("Logging to file: %s", *logFile)
	}

	if !isNmapInstalled() {
		log.Fatal("Error: Nmap is not installed or not in the system's PATH. This program is a wrapper and requires Nmap to function.")
	}

	if *concurrentScans < 1 {
		log.Fatal("Error: Number of concurrent scans must be at least 1")
	}

	isPQCCheck = *pqcCheck
	if isPQCCheck && !isTestSSLInstalled() {
		log.Fatal("Error: testssl.sh is not installed or not in PATH. Install from: https://github.com/drwetter/testssl.sh")
	}

	var k8sClient *K8sClient
	var allPodsInfo []PodInfo

	if *allPods {
		var err error
		k8sClient, err = newK8sClient()
		if err != nil {
			log.Fatalf("Could not create kubernetes client for --all-pods: %v", err)
		}
		allPodsInfo = getFilteredPods(k8sClient, *componentFilter, *namespaceFilter, *limitIPs)
	}

	var scanResults ScanResults

	switch {
	case len(allPodsInfo) > 0:
		if isPQCCheck {
			scanResults = performPQCClusterScan(allPodsInfo, *concurrentScans, k8sClient)
		} else {
			scanResults = performClusterScan(allPodsInfo, *concurrentScans, k8sClient)
		}

	case *targets != "":
		if isPQCCheck {
			scanResults = performPQCScan(strings.Split(*targets, ","), *concurrentScans)
		} else {
			targetsByHost := parseTargetsByHost(strings.Split(*targets, ","))
			scanResults = performTargetsScan(targetsByHost, *concurrentScans)
		}

	default:
		if isPQCCheck {
			scanResults = performPQCScan([]string{fmt.Sprintf("%s:%s", *host, *port)}, *concurrentScans)
		} else {
			scanResults = performSingleHostScan(*host, *port, k8sClient)
		}
	}

	finalScanResults = &scanResults

	writeOutputFiles(scanResults, *artifactDir, *jsonFile, *csvFile, *junitFile)
	if *jsonFile == "" && *csvFile == "" && *junitFile == "" {
		if isPQCCheck {
			printPQCClusterResults(scanResults)
		} else if len(allPodsInfo) > 0 || *targets != "" {
			printClusterResults(scanResults)
		} else {
			printParsedResults(scanResults)
		}
	}
}

// getFilteredPods fetches all pods from the cluster and applies component,
// namespace, and IP-limit filters. Shared by both PQC and default scan modes.
func getFilteredPods(k8sClient *K8sClient, componentFilter, namespaceFilter string, limitIPs int) []PodInfo {
	allPodsInfo := k8sClient.getAllPodsInfo()

	if componentFilter != "" {
		log.Printf("Filtering pods by component name(s): %s", componentFilter)
		filterComponents := strings.Split(componentFilter, ",")
		filterSet := make(map[string]struct{})
		for _, c := range filterComponents {
			filterSet[strings.TrimSpace(c)] = struct{}{}
		}

		var filteredPods []PodInfo
		for _, pod := range allPodsInfo {
			component, err := k8sClient.getOpenshiftComponentFromImage(pod.Image)
			if err != nil {
				log.Printf("Warning: could not get component for image %s: %v", pod.Image, err)
				continue
			}
			if _, ok := filterSet[component.Component]; ok {
				filteredPods = append(filteredPods, pod)
			}
		}
		log.Printf("Filtered pods: %d remaining out of %d", len(filteredPods), len(allPodsInfo))
		allPodsInfo = filteredPods
	}

	if namespaceFilter != "" {
		log.Printf("Filtering pods by namespace(s): %s", namespaceFilter)
		filterNamespaces := strings.Split(namespaceFilter, ",")
		filterSet := make(map[string]struct{})
		for _, ns := range filterNamespaces {
			filterSet[strings.TrimSpace(ns)] = struct{}{}
		}

		var filteredPods []PodInfo
		for _, pod := range allPodsInfo {
			if _, ok := filterSet[pod.Namespace]; ok {
				filteredPods = append(filteredPods, pod)
			}
		}
		log.Printf("Filtered pods by namespace: %d remaining out of %d", len(filteredPods), len(allPodsInfo))
		allPodsInfo = filteredPods
	}

	log.Printf("Found %d pods to scan from the cluster.", len(allPodsInfo))

	if limitIPs > 0 {
		totalIPs := 0
		for _, pod := range allPodsInfo {
			totalIPs += len(pod.IPs)
		}
		if totalIPs > limitIPs {
			log.Printf("Limiting scan to %d IPs (found %d total IPs)", limitIPs, totalIPs)
			allPodsInfo = limitPodsToIPCount(allPodsInfo, limitIPs)
			limitedTotal := 0
			for _, pod := range allPodsInfo {
				limitedTotal += len(pod.IPs)
			}
			log.Printf("After limiting: %d pods with %d total IPs", len(allPodsInfo), limitedTotal)
		}
	}

	return allPodsInfo
}

// parseTargetsByHost parses a list of "host:port" strings into a map of host -> ports.
func parseTargetsByHost(targetList []string) map[string][]string {
	if len(targetList) == 0 || (len(targetList) == 1 && targetList[0] == "") {
		log.Fatal("Error: --targets flag provided but no targets were specified")
	}

	targetsByHost := make(map[string][]string)
	for _, t := range targetList {
		parts := strings.Split(t, ":")
		if len(parts) != 2 {
			log.Printf("Warning: Skipping invalid target format: %s (expected host:port)", t)
			continue
		}
		host := parts[0]
		port := parts[1]
		targetsByHost[host] = append(targetsByHost[host], port)
	}

	if len(targetsByHost) == 0 {
		log.Fatal("Error: No valid targets found in --targets flag")
	}

	return targetsByHost
}

// performSingleHostScan runs an nmap TLS scan against a single host:port.
func performSingleHostScan(host, port string, k8sClient *K8sClient) ScanResults {
	log.Printf("Found Nmap. Starting scan on %s:%s...\n\n", host, port)

	cmd := exec.Command("nmap", "-Pn", "-sV", "--script", "ssl-enum-ciphers", "-p", port, "-oX", "-", host)
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Fatalf("Error executing Nmap command. Nmap output:\n%s", string(output))
	}

	var scanResult ScanRun
	if err := xml.Unmarshal(output, &scanResult); err != nil {
		log.Fatalf("Error parsing Nmap XML output: %v", err)
	}

	var tlsConfig *TLSSecurityProfile
	if k8sClient != nil {
		if config, err := k8sClient.getTLSSecurityProfile(); err != nil {
			log.Printf("Warning: Could not collect TLS security profiles: %v", err)
		} else {
			tlsConfig = config
		}
	}

	singleResult := ScanResults{
		Timestamp:         time.Now().Format(time.RFC3339),
		TotalIPs:          1,
		ScannedIPs:        1,
		TLSSecurityConfig: tlsConfig,
		IPResults: []IPResult{{
			IP:          host,
			Status:      "scanned",
			OpenPorts:   []int{},
			PortResults: []PortResult{},
		}},
	}

	if len(scanResult.Hosts) > 0 && len(scanResult.Hosts[0].Ports) > 0 {
		for _, tlsPort := range scanResult.Hosts[0].Ports {
			if portNum, err := strconv.Atoi(tlsPort.PortID); err == nil {
				singleResult.IPResults[0].OpenPorts = append(singleResult.IPResults[0].OpenPorts, portNum)
				portResult := PortResult{
					Port:     portNum,
					Protocol: tlsPort.Protocol,
					State:    tlsPort.State.State,
					Service:  tlsPort.Service.Name,
				}
				portResult.TlsVersions, portResult.TlsCiphers, portResult.TlsCipherStrength = extractTLSInfo(scanResult)

				if tlsConfig != nil && len(portResult.TlsCiphers) > 0 {
					checkCompliance(&portResult, tlsConfig)
				}

				singleResult.IPResults[0].PortResults = append(singleResult.IPResults[0].PortResults, portResult)
			}
		}
	}

	return singleResult
}

func writeJUnitOutput(scanResults ScanResults, filename string) error {
	testSuite := JUnitTestSuite{
		Name: "TLSSecurityScan",
	}

	for _, ipResult := range scanResults.IPResults {
		for _, portResult := range ipResult.PortResults {
			testCase := JUnitTestCase{
				Name:      fmt.Sprintf("%s:%d - %s", ipResult.IP, portResult.Port, portResult.Service),
				ClassName: ipResult.Pod.Name,
			}

			var failures []string
			if portResult.IngressTLSConfigCompliance != nil && (!portResult.IngressTLSConfigCompliance.Version || !portResult.IngressTLSConfigCompliance.Ciphers) {
				failures = append(failures, "Ingress TLS config is not compliant.")
			}
			if portResult.APIServerTLSConfigCompliance != nil && (!portResult.APIServerTLSConfigCompliance.Version || !portResult.APIServerTLSConfigCompliance.Ciphers) {
				failures = append(failures, "API Server TLS config is not compliant.")
			}
			if portResult.KubeletTLSConfigCompliance != nil && (!portResult.KubeletTLSConfigCompliance.Version || !portResult.KubeletTLSConfigCompliance.Ciphers) {
				failures = append(failures, "Kubelet TLS config is not compliant.")
			}

			if len(failures) > 0 {
				testCase.Failure = &JUnitFailure{
					Message: "TLS Compliance Failed",
					Type:    "TLSComplianceCheck",
					Content: strings.Join(failures, "\n"),
				}
				testSuite.Failures++
			}

			testSuite.TestCases = append(testSuite.TestCases, testCase)
		}
	}

	testSuite.Tests = len(testSuite.TestCases)

	// Create the directory for the file if it doesn't exist
	dir := filepath.Dir(filename)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("could not create directory for JUnit report: %v", err)
	}

	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("could not create JUnit report file: %v", err)
	}
	defer file.Close()

	if _, err := file.WriteString(xml.Header); err != nil {
		return fmt.Errorf("failed to write XML header to JUnit report: %v", err)
	}

	encoder := xml.NewEncoder(file)
	encoder.Indent("", "  ")
	if err := encoder.Encode(testSuite); err != nil {
		return fmt.Errorf("could not encode JUnit report: %v", err)
	}

	return nil
}

func isNmapInstalled() bool {
	_, err := exec.LookPath("nmap")
	return err == nil
}

// discoverPortsFromPodSpec discovers open ports by reading the pod's specification from the Kubernetes API.
// This is much more reliable and efficient than network scanning.
func discoverPortsFromPodSpec(pod *v1.Pod) ([]int, error) {
	log.Printf("Discovering ports for pod %s/%s from API server...", pod.Namespace, pod.Name)

	var ports []int
	for _, container := range pod.Spec.Containers {
		for _, port := range container.Ports {
			// We only care about TCP ports for TLS scanning
			if port.Protocol == v1.ProtocolTCP {
				ports = append(ports, int(port.ContainerPort))
			}
		}
	}

	// Also check init containers, just in case they expose a port
	for _, container := range pod.Spec.InitContainers {
		for _, port := range container.Ports {
			if port.Protocol == v1.ProtocolTCP {
				ports = append(ports, int(port.ContainerPort))
			}
		}
	}

	if len(ports) == 0 {
		log.Printf("Found 0 declared TCP ports for pod %s/%s.", pod.Namespace, pod.Name)
	} else {
		log.Printf("Found %d declared TCP ports for pod %s/%s: %v", len(ports), pod.Namespace, pod.Name, ports)
	}

	return ports, nil
}

func getMinVersionValue(versions []string) int {
	if len(versions) == 0 {
		return 0
	}
	minVersion := tlsVersionValueMap[versions[0]]
	for _, v := range versions[1:] {
		verVal := tlsVersionValueMap[v]
		if verVal < minVersion {
			minVersion = verVal
		}
	}
	return minVersion
}

func checkCompliance(portResult *PortResult, tlsProfile *TLSSecurityProfile) {
	portResultMinVersion := 0
	if portResult.TlsVersions != nil {
		portResultMinVersion = getMinVersionValue(portResult.TlsVersions)
	}

	// TODO potentially wasteful memory allocations here
	portResult.IngressTLSConfigCompliance = &TLSConfigComplianceResult{}
	portResult.APIServerTLSConfigCompliance = &TLSConfigComplianceResult{}
	portResult.KubeletTLSConfigCompliance = &TLSConfigComplianceResult{}

	if ingress := tlsProfile.IngressController; tlsProfile.IngressController != nil {
		if ingress.MinTLSVersion != "" {
			ingressMinVersion := tlsVersionValueMap[ingress.MinTLSVersion]
			portResult.IngressTLSConfigCompliance.Version = (portResultMinVersion >= ingressMinVersion)
		}
		portResult.IngressTLSConfigCompliance.Ciphers = checkCipherCompliance(portResult.TlsCiphers, ingress.Ciphers)
	}

	if api := tlsProfile.APIServer; tlsProfile.APIServer != nil {
		if api.MinTLSVersion != "" {
			apiMinVersion := tlsVersionValueMap[api.MinTLSVersion]
			portResult.APIServerTLSConfigCompliance.Version = (portResultMinVersion >= apiMinVersion)
		}
		portResult.APIServerTLSConfigCompliance.Ciphers = checkCipherCompliance(portResult.TlsCiphers, api.Ciphers)
	}

	if kube := tlsProfile.KubeletConfig; tlsProfile.KubeletConfig != nil {
		if kube.MinTLSVersion != "" {
			kubMinVersion := tlsVersionValueMap[kube.MinTLSVersion]
			portResult.KubeletTLSConfigCompliance.Version = (portResultMinVersion >= kubMinVersion)
		}
		portResult.KubeletTLSConfigCompliance.Ciphers = checkCipherCompliance(portResult.TlsCiphers, kube.TLSCipherSuites)
	}

}

func checkCipherCompliance(gotCiphers []string, expectedCiphers []string) bool {
	expectedSet := make(map[string]struct{}, len(expectedCiphers))
	for _, c := range expectedCiphers {
		expectedSet[c] = struct{}{}
	}

	if len(gotCiphers) == 0 && len(expectedCiphers) > 0 {
		return false
	}
	// TODO nmap prints some cipher suites to specify that an "authenticated key exchange", AKE was used
	// We need a way to map these cipher suites to the more generic version.
	// for example TLS_AKE_WITH_AES_128_GCM_SHA256 (nmap) -> TLS_AES_128_GCM_SHA256 (openssl)

	for _, cipher := range gotCiphers {
		convertedCipher := ianaCipherToOpenSSLCipherMap[cipher]
		if _, exists := expectedSet[convertedCipher]; !exists {
			return false
		}
	}

	return true
}

// hasComplianceFailures checks if any port has TLS compliance violations
func hasComplianceFailures(results ScanResults) bool {
	for _, ipResult := range results.IPResults {
		for _, portResult := range ipResult.PortResults {
			// Check Ingress compliance
			if portResult.IngressTLSConfigCompliance != nil &&
				(!portResult.IngressTLSConfigCompliance.Version || !portResult.IngressTLSConfigCompliance.Ciphers) {
				return true
			}
			// Check API Server compliance
			if portResult.APIServerTLSConfigCompliance != nil &&
				(!portResult.APIServerTLSConfigCompliance.Version || !portResult.APIServerTLSConfigCompliance.Ciphers) {
				return true
			}
			// Check Kubelet compliance
			if portResult.KubeletTLSConfigCompliance != nil &&
				(!portResult.KubeletTLSConfigCompliance.Version || !portResult.KubeletTLSConfigCompliance.Ciphers) {
				return true
			}
		}
	}
	return false
}

// hasPQCComplianceFailures checks if any port fails PQC compliance
// (requires TLS 1.3 AND ML-KEM support: x25519mlkem768 or mlkem768)
func hasPQCComplianceFailures(results ScanResults) bool {
	for _, ipResult := range results.IPResults {
		for _, portResult := range ipResult.PortResults {
			if portResult.Status == StatusNoPorts {
				continue
			}

			if !portResult.TLS13Supported {
				log.Printf("PQC compliance failure: %s:%d - TLS 1.3 not supported", ipResult.IP, portResult.Port)
				return true
			}

			if !portResult.MLKEMSupported {
				log.Printf("PQC compliance failure: %s:%d - ML-KEM not supported (no x25519mlkem768 or mlkem768)", ipResult.IP, portResult.Port)
				return true
			}

			hasValidMLKEM := false
			for _, kem := range portResult.MLKEMCiphers {
				kemLower := strings.ToLower(kem)
				if strings.Contains(kemLower, "x25519mlkem768") || strings.Contains(kemLower, "mlkem768") {
					hasValidMLKEM = true
					break
				}
			}
			if !hasValidMLKEM {
				log.Printf("PQC compliance failure: %s:%d - No valid ML-KEM KEM found (need x25519mlkem768 or mlkem768)", ipResult.IP, portResult.Port)
				return true
			}
		}
	}
	return false
}

// TODO move to helpers
// stringInSlice returns true if the string s is present in slice list.
func stringInSlice(s string, list []string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func extractTLSInfo(scanRun ScanRun) (versions []string, ciphers []string, cipherStrength map[string]string) {
	// Collect all detected ciphers and TLS versions for this port
	var allDetectedCiphers []string
	var tlsVersions []string
	cipherStrength = make(map[string]string) // TODO currently unused. Might be useful

	// Extract TLS versions and ciphers from scan results
	for _, host := range scanRun.Hosts {
		for _, tlsPort := range host.Ports {
			for _, script := range tlsPort.Scripts {
				if script.ID == "ssl-enum-ciphers" {
					for _, table := range script.Tables {
						tlsVersion := table.Key
						if tlsVersion != "" {
							tlsVersions = append(tlsVersions, tlsVersion)
						}

						// Find ciphers for this TLS version
						for _, subTable := range table.Tables {
							if subTable.Key == "ciphers" {
								var currentCipherName string
								var currentCipherStrength string
								for _, cipherTable := range subTable.Tables {
									currentCipherName = ""
									currentCipherStrength = ""
									for _, elem := range cipherTable.Elems {
										if elem.Key == "name" {
											currentCipherName = elem.Value
										} else if elem.Key == "strength" {
											currentCipherStrength = elem.Value
										}
									}
									if currentCipherName != "" && currentCipherStrength != "" {
										allDetectedCiphers = append(allDetectedCiphers, currentCipherName)
										cipherStrength[currentCipherName] = currentCipherStrength
									}
								}
							}
						}
					}
				}
			}
		}
	}

	// Remove duplicates
	allDetectedCiphers = removeDuplicates(allDetectedCiphers)
	tlsVersions = removeDuplicates(tlsVersions)

	return tlsVersions, allDetectedCiphers, cipherStrength
}

func performClusterScan(allPodsInfo []PodInfo, concurrentScans int, k8sClient *K8sClient) ScanResults {
	startTime := time.Now()

	totalIPs := 0
	for _, pod := range allPodsInfo {
		totalIPs += len(pod.IPs)
	}

	fmt.Printf("========================================\n")
	fmt.Printf("CONCURRENT CLUSTER SCAN STARTING\n")
	fmt.Printf("========================================\n")
	fmt.Printf("Total Pods to scan: %d\n", len(allPodsInfo))
	fmt.Printf("Total IPs to scan: %d\n", totalIPs)
	fmt.Printf("Concurrent workers: %d\n", concurrentScans)
	fmt.Printf("Process detection workers: %d\n", max(2, concurrentScans/2))
	fmt.Printf("========================================\n\n")

	// Collect TLS security configuration from cluster
	var tlsConfig *TLSSecurityProfile
	if k8sClient != nil {
		if config, err := k8sClient.getTLSSecurityProfile(); err != nil {
			log.Printf("Warning: Could not collect TLS security profiles: %v", err)
		} else {
			tlsConfig = config
		}
	}

	results := ScanResults{
		Timestamp:         startTime.Format(time.RFC3339),
		TotalIPs:          totalIPs,
		IPResults:         make([]IPResult, 0, totalIPs),
		TLSSecurityConfig: tlsConfig,
	}

	// Create a channel to send PodInfo to workers
	podChan := make(chan PodInfo, len(allPodsInfo))

	// Use a WaitGroup to wait for all workers to complete
	var wg sync.WaitGroup
	var mu sync.Mutex

	// Start worker goroutines
	for w := 0; w < concurrentScans; w++ {
		workerID := w + 1
		log.Printf("Starting WORKER %d", workerID)
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for pod := range podChan {
				log.Printf("WORKER %d: Processing Pod %s/%s", workerID, pod.Namespace, pod.Name)

				component, err := k8sClient.getOpenshiftComponentFromImage(pod.Image)
				if err != nil {
					log.Printf("Could not get openshift component for image %s: %v", pod.Image, err)
				}

				for _, ip := range pod.IPs {
					ipResult := scanIP(k8sClient, ip, pod, tlsConfig)
					ipResult.OpenshiftComponent = component

					mu.Lock()
					results.IPResults = append(results.IPResults, ipResult)
					results.ScannedIPs++
					mu.Unlock()
					log.Printf("WORKER %d: Completed %s (%d/%d IPs done)", workerID, ip, results.ScannedIPs, totalIPs)
				}
			}
			log.Printf("WORKER %d: FINISHED", workerID)
		}(workerID)
	}

	// Send PodInfo to workers
	for _, pod := range allPodsInfo {
		podChan <- pod
	}
	close(podChan)

	// Wait for all workers to complete
	wg.Wait()

	duration := time.Since(startTime)

	fmt.Printf("\n========================================\n")
	fmt.Printf("CONCURRENT CLUSTER SCAN COMPLETE!\n")
	fmt.Printf("========================================\n")
	fmt.Printf("Total IPs processed: %d\n", results.ScannedIPs)
	fmt.Printf("Total time: %v\n", duration)
	fmt.Printf("Concurrent workers used: %d\n", concurrentScans)
	fmt.Printf("Average time per IP: %.2fs\n", duration.Seconds()/float64(results.ScannedIPs))
	fmt.Printf("========================================\n")

	return results
}

func scanIP(k8sClient *K8sClient, ip string, pod PodInfo, tlsSecurityProfile *TLSSecurityProfile) IPResult {
	openPorts, err := discoverPortsFromPodSpec(pod.Pod)
	if err != nil {
		return IPResult{
			IP:     ip,
			Pod:    &pod,
			Status: "error",
			Error:  fmt.Sprintf("port discovery failed: %v", err),
		}
	}

	if len(openPorts) == 0 {
		return IPResult{
			IP:        ip,
			Pod:       &pod,
			Status:    "scanned",
			OpenPorts: []int{},
			PortResults: []PortResult{{
				Port:   0,
				Status: StatusNoPorts,
				Reason: "Pod declares no TCP ports in spec",
			}},
		}
	}

	// Run lsof BEFORE scanning to get listen address information
	if k8sClient != nil && len(pod.Containers) > 0 {
		k8sClient.getAndCachePodProcesses(pod)
	}

	ipResult := IPResult{
		IP:          ip,
		Pod:         &pod,
		Status:      "scanned",
		OpenPorts:   openPorts,
		PortResults: make([]PortResult, 0, len(openPorts)),
	}

	// Check for localhost-only ports and filter them out before nmap scan
	var portsToScan []int
	localhostOnlyPorts := make(map[int]string) // port -> listen address

	for _, port := range openPorts {
		if k8sClient != nil {
			if isLocalhost, listenAddr := k8sClient.isLocalhostOnly(ip, port); isLocalhost {
				localhostOnlyPorts[port] = listenAddr
				log.Printf("Port %d on %s is bound to localhost only (%s), skipping network scan", port, ip, listenAddr)
				continue
			}
		}
		portsToScan = append(portsToScan, port)
	}

	// Add localhost-only ports to results immediately
	for port, listenAddr := range localhostOnlyPorts {
		portResult := PortResult{
			Port:          port,
			Protocol:      "tcp",
			State:         "localhost",
			Status:        StatusLocalhostOnly,
			Reason:        fmt.Sprintf("Bound to %s, not accessible from pod IP", listenAddr),
			ListenAddress: listenAddr,
		}
		// Get process name if available
		if k8sClient != nil {
			k8sClient.processCacheMutex.Lock()
			if processName, ok := k8sClient.processNameMap[ip][port]; ok {
				portResult.ProcessName = processName
				portResult.ContainerName = strings.Join(pod.Containers, ",")
			}
			k8sClient.processCacheMutex.Unlock()
		}
		ipResult.PortResults = append(ipResult.PortResults, portResult)
	}

	// If no ports to scan via network, return early
	if len(portsToScan) == 0 {
		log.Printf("All ports for %s are localhost-only, no network scan needed", ip)
		return ipResult
	}

	// Convert port numbers to a comma-separated string for nmap
	portStrings := make([]string, len(portsToScan))
	for i, p := range portsToScan {
		portStrings[i] = strconv.Itoa(p)
	}
	portSpec := strings.Join(portStrings, ",")

	log.Printf("Scanning %s ports on %s", portSpec, ip)
	cmd := exec.Command("nmap", "-Pn", "-sV", "--script", "ssl-enum-ciphers", "-p", portSpec, "-oX", "-", ip)
	log.Printf("Running command: %s", cmd.String())
	output, err := cmd.CombinedOutput()
	log.Printf("Command output: %s", string(output))
	if err != nil {
		ipResult.Error = fmt.Sprintf("nmap scan failed: %v", err)
		// Still create PortResult entries for CSV consistency
		for _, port := range portsToScan {
			ipResult.PortResults = append(ipResult.PortResults, PortResult{
				Port:   port,
				Error:  "nmap scan failed",
				Status: StatusError,
				Reason: fmt.Sprintf("nmap scan failed: %v", err),
			})
		}
		return ipResult
	}

	var scanResult ScanRun
	if err := xml.Unmarshal(output, &scanResult); err != nil {
		ipResult.Error = fmt.Sprintf("failed to parse scan XML: %v", err)
		for _, port := range portsToScan {
			ipResult.PortResults = append(ipResult.PortResults, PortResult{
				Port:   port,
				Error:  "scan xml parse failed",
				Status: StatusError,
				Reason: "Failed to parse scan XML output",
			})
		}
		return ipResult
	}

	// Create a map of port results from the scan run
	resultsByPort := make(map[string]PortResult)
	if len(scanResult.Hosts) > 0 {
		for _, tlsPort := range scanResult.Hosts[0].Ports {
			portNum, _ := strconv.Atoi(tlsPort.PortID)
			singlePortRun := ScanRun{Hosts: []Host{{Ports: []Port{tlsPort}}}}
			portResult := PortResult{
				Port:     portNum,
				Protocol: tlsPort.Protocol,
				State:    tlsPort.State.State,
				Service:  tlsPort.Service.Name,
			}
			portResult.TlsVersions, portResult.TlsCiphers, portResult.TlsCipherStrength = extractTLSInfo(singlePortRun)

			// Set status and reason based on scan results
			portResult.Status, portResult.Reason = categorizePortResult(portResult, tlsPort)

			resultsByPort[tlsPort.PortID] = portResult
		}
	}

	// Correlate results with discovered ports
	for _, port := range portsToScan {
		if portResult, ok := resultsByPort[strconv.Itoa(port)]; ok {
			// Log port state for debugging
			if portResult.State == "filtered" {
				log.Printf("Port %d on %s is filtered (not accessible). This may be due to firewall rules, network policies, or the service not listening on this IP. TLS information will be N/A.", port, ip)
			} else if portResult.State != "open" {
				log.Printf("Port %d on %s has state '%s'. TLS information may be unavailable.", port, ip, portResult.State)
			}

			// Check compliance and get process info if TLS data was found
			if len(portResult.TlsCiphers) > 0 {
				log.Printf("Found TLS information for port %d on %s: %d ciphers, versions: %v", port, ip, len(portResult.TlsCiphers), portResult.TlsVersions)
				checkCompliance(&portResult, tlsSecurityProfile)

				if k8sClient != nil && len(pod.Containers) > 0 {
					k8sClient.processCacheMutex.Lock()
					if processName, ok := k8sClient.processNameMap[ip][port]; ok {
						portResult.ProcessName = processName
						portResult.ContainerName = strings.Join(pod.Containers, ",")
						log.Printf("Identified process for port %d on %s: %s", port, ip, processName)
					}
					k8sClient.processCacheMutex.Unlock()
				}
			} else {
				log.Printf("No TLS information found for port %d on %s (state: %s). This port may not be listening, may be blocked by network policies, or may not be a TLS service.", port, ip, portResult.State)
			}

			// Get listen address info if available
			if k8sClient != nil {
				if info, ok := k8sClient.getListenInfo(ip, port); ok {
					portResult.ListenAddress = info.ListenAddress
				}
			}

			ipResult.PortResults = append(ipResult.PortResults, portResult)
		} else {
			// Port was discovered but not in the ssl-enum-ciphers result (e.g., not an SSL port)
			log.Printf("Port %d on %s was declared in pod spec but not found in nmap results. Assuming non-TLS service.", port, ip)
			ipResult.PortResults = append(ipResult.PortResults, PortResult{
				Port:   port,
				State:  "open",
				Status: StatusNoTLS,
				Reason: "Port open but no TLS detected (plain HTTP/TCP)",
			})
		}
	}

	return ipResult
}

// categorizePortResult determines the Status and Reason based on scan results
func categorizePortResult(portResult PortResult, tlsPort Port) (ScanStatus, string) {
	// Check if TLS was successfully detected
	if len(portResult.TlsCiphers) > 0 {
		return StatusOK, "TLS scan successful"
	}

	// Categorize based on port state
	switch portResult.State {
	case "filtered":
		return StatusFiltered, "Network policy or firewall blocking access"
	case "closed":
		return StatusClosed, "Port not listening on this IP"
	case "open":
		// Port is open but no TLS - check for specific error patterns
		// Check if it might be mTLS required (handshake failure patterns)
		for _, script := range tlsPort.Scripts {
			if script.ID == "ssl-enum-ciphers" {
				for _, elem := range script.Elems {
					if strings.Contains(strings.ToLower(elem.Value), "handshake") ||
						strings.Contains(strings.ToLower(elem.Value), "certificate") {
						return StatusMTLSRequired, "TLS handshake failed - may require client certificate"
					}
				}
			}
		}
		// Check for timeout patterns
		if tlsPort.State.Reason == "no-response" {
			return StatusTimeout, "Connection timed out"
		}
		// Default: port is open but not using TLS
		return StatusNoTLS, "Port open but no TLS detected (plain HTTP/TCP)"
	default:
		return StatusError, fmt.Sprintf("Unknown port state: %s", portResult.State)
	}
}

// limitPodsToIPCount limits the pod list to contain at most maxIPs total IP addresses
func limitPodsToIPCount(allPodsInfo []PodInfo, maxIPs int) []PodInfo {
	if maxIPs <= 0 {
		return allPodsInfo
	}

	var limitedPods []PodInfo
	currentIPCount := 0

	for _, pod := range allPodsInfo {
		if currentIPCount >= maxIPs {
			break
		}

		// If this pod would exceed the limit, include only some of its IPs
		if currentIPCount+len(pod.IPs) > maxIPs {
			remainingIPs := maxIPs - currentIPCount
			limitedPod := pod
			limitedPod.IPs = pod.IPs[:remainingIPs]
			limitedPods = append(limitedPods, limitedPod)
			break
		}

		// Include the entire pod
		limitedPods = append(limitedPods, pod)
		currentIPCount += len(pod.IPs)
	}

	return limitedPods
}

func performTargetsScan(targetsByHost map[string][]string, concurrentScans int) ScanResults {
	startTime := time.Now()

	totalIPs := len(targetsByHost)

	fmt.Printf("========================================\n")
	fmt.Printf("TARGETS SCAN STARTING\n")
	fmt.Printf("========================================\n")
	fmt.Printf("Total hosts to scan: %d\n", totalIPs)
	fmt.Printf("Concurrent workers: %d\n", concurrentScans)
	fmt.Printf("========================================\n\n")

	results := ScanResults{
		Timestamp: startTime.Format(time.RFC3339),
		TotalIPs:  totalIPs,
		IPResults: make([]IPResult, 0, totalIPs),
	}

	type targetJob struct {
		host  string
		ports []string
	}

	// Create a channel to send targets to workers
	targetChan := make(chan targetJob, totalIPs)

	// Use a WaitGroup to wait for all workers to complete
	var wg sync.WaitGroup
	var mu sync.Mutex

	// Start worker goroutines
	for w := 0; w < concurrentScans; w++ {
		workerID := w + 1
		log.Printf("Starting WORKER %d", workerID)
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for job := range targetChan {
				log.Printf("WORKER %d: Processing host %s", workerID, job.host)
				ipResult := scanHostPorts(job.host, job.ports)

				mu.Lock()
				results.IPResults = append(results.IPResults, ipResult)
				results.ScannedIPs++
				mu.Unlock()
				log.Printf("WORKER %d: Completed %s (%d/%d hosts done)", workerID, job.host, results.ScannedIPs, totalIPs)
			}
			log.Printf("WORKER %d: FINISHED", workerID)
		}(workerID)
	}

	// Send targets to workers
	for host, ports := range targetsByHost {
		targetChan <- targetJob{host: host, ports: ports}
	}
	close(targetChan)

	// Wait for all workers to complete
	wg.Wait()

	duration := time.Since(startTime)

	fmt.Printf("\n========================================\n")
	fmt.Printf("TARGETS SCAN COMPLETE!\n")
	fmt.Printf("========================================\n")
	fmt.Printf("Total hosts processed: %d\n", results.ScannedIPs)
	fmt.Printf("Total time: %v\n", duration)
	fmt.Printf("Concurrent workers used: %d\n", concurrentScans)
	if results.ScannedIPs > 0 {
		fmt.Printf("Average time per host: %.2fs\n", duration.Seconds()/float64(results.ScannedIPs))
	}
	fmt.Printf("========================================\n")

	return results
}

func scanHostPorts(host string, ports []string) IPResult {
	portSpec := strings.Join(ports, ",")
	log.Printf("Scanning SSL ciphers on %s for ports: %s", host, portSpec)

	ipResult := IPResult{
		IP:          host,
		Status:      "scanned",
		PortResults: make([]PortResult, 0, len(ports)),
	}
	for _, pStr := range ports {
		p, _ := strconv.Atoi(pStr)
		ipResult.OpenPorts = append(ipResult.OpenPorts, p)
	}

	cmd := exec.Command("nmap", "-Pn", "-sV", "--script", "ssl-enum-ciphers", "-p", portSpec, "-oX", "-", host)
	output, err := cmd.CombinedOutput()
	if err != nil {
		ipResult.Error = fmt.Sprintf("nmap scan failed: %v", err)
		for _, portStr := range ports {
			port, _ := strconv.Atoi(portStr)
			ipResult.PortResults = append(ipResult.PortResults, PortResult{
				Port:   port,
				Error:  "nmap scan failed",
				Status: StatusError,
				Reason: fmt.Sprintf("nmap scan failed: %v", err),
			})
		}
		return ipResult
	}

	var scanResult ScanRun
	if err := xml.Unmarshal(output, &scanResult); err != nil {
		ipResult.Error = fmt.Sprintf("failed to parse scan XML: %v", err)
		for _, portStr := range ports {
			port, _ := strconv.Atoi(portStr)
			ipResult.PortResults = append(ipResult.PortResults, PortResult{
				Port:   port,
				Error:  "scan xml parse failed",
				Status: StatusError,
				Reason: "Failed to parse scan XML output",
			})
		}
		return ipResult
	}

	resultsByPort := make(map[string]PortResult)
	if len(scanResult.Hosts) > 0 {
		for _, tlsPort := range scanResult.Hosts[0].Ports {
			portNum, _ := strconv.Atoi(tlsPort.PortID)
			singlePortRun := ScanRun{Hosts: []Host{{Ports: []Port{tlsPort}}}}
			portResult := PortResult{
				Port:     portNum,
				Protocol: tlsPort.Protocol,
				State:    tlsPort.State.State,
				Service:  tlsPort.Service.Name,
			}
			portResult.TlsVersions, portResult.TlsCiphers, portResult.TlsCipherStrength = extractTLSInfo(singlePortRun)
			// Set status and reason based on scan results
			portResult.Status, portResult.Reason = categorizePortResult(portResult, tlsPort)
			resultsByPort[tlsPort.PortID] = portResult
		}
	}

	for _, portStr := range ports {
		port, _ := strconv.Atoi(portStr)
		if portResult, ok := resultsByPort[portStr]; ok {
			ipResult.PortResults = append(ipResult.PortResults, portResult)
		} else {
			// Port was specified but not in the result (e.g., not an SSL port or closed)
			ipResult.PortResults = append(ipResult.PortResults, PortResult{
				Port:   port,
				State:  "closed/filtered",
				Status: StatusClosed,
				Reason: "Port not responding or filtered",
			})
		}
	}

	return ipResult
}

// isTestSSLInstalled checks if testssl.sh is available in PATH
func isTestSSLInstalled() bool {
	_, err := exec.LookPath("testssl.sh")
	return err == nil
}

// performPQCScan performs a PQC check on a list of host:port targets (no k8s)
func performPQCScan(targets []string, concurrentScans int) ScanResults {
	startTime := time.Now()

	fmt.Printf("========================================\n")
	fmt.Printf("PQC CHECK: TLS 1.3 + ML-KEM SCAN\n")
	fmt.Printf("========================================\n")
	fmt.Printf("TLS Version: testssl.sh -p (protocols only)\n")
	fmt.Printf("ML-KEM:      testssl.sh -f (KEMs offered)\n")
	fmt.Printf("Targets:     %d\n", len(targets))
	fmt.Printf("Workers:     %d\n", concurrentScans)
	fmt.Printf("========================================\n\n")

	results := ScanResults{
		Timestamp: startTime.Format(time.RFC3339),
		TotalIPs:  len(targets),
		IPResults: make([]IPResult, 0, len(targets)),
	}

	targetChan := make(chan string, len(targets))
	var wg sync.WaitGroup
	var mu sync.Mutex

	for w := 0; w < concurrentScans; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for target := range targetChan {
				ipResult := scanPQCTarget(target)
				mu.Lock()
				results.IPResults = append(results.IPResults, ipResult)
				results.ScannedIPs++
				mu.Unlock()
			}
		}()
	}

	for _, target := range targets {
		targetChan <- target
	}
	close(targetChan)

	wg.Wait()

	return results
}

// performPQCClusterScan performs a PQC check on cluster pods with component info
func performPQCClusterScan(allPodsInfo []PodInfo, concurrentScans int, k8sClient *K8sClient) ScanResults {
	startTime := time.Now()

	totalIPs := 0
	for _, pod := range allPodsInfo {
		totalIPs += len(pod.IPs)
	}

	fmt.Printf("========================================\n")
	fmt.Printf("PQC CLUSTER SCAN: TLS 1.3 + ML-KEM\n")
	fmt.Printf("========================================\n")
	fmt.Printf("TLS Version: testssl.sh -p (protocols only)\n")
	fmt.Printf("ML-KEM:      testssl.sh -f (KEMs offered)\n")
	fmt.Printf("Pods:        %d\n", len(allPodsInfo))
	fmt.Printf("Total IPs:   %d\n", totalIPs)
	fmt.Printf("Workers:     %d\n", concurrentScans)
	fmt.Printf("========================================\n\n")

	results := ScanResults{
		Timestamp: startTime.Format(time.RFC3339),
		TotalIPs:  totalIPs,
		IPResults: make([]IPResult, 0, totalIPs),
	}

	podChan := make(chan PodInfo, len(allPodsInfo))
	var wg sync.WaitGroup
	var mu sync.Mutex

	for w := 0; w < concurrentScans; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for pod := range podChan {
				var component *OpenshiftComponent
				if k8sClient != nil {
					comp, err := k8sClient.getOpenshiftComponentFromImage(pod.Image)
					if err != nil {
						log.Printf("Could not get component for image %s: %v", pod.Image, err)
					} else {
						component = comp
					}
				}

				// Discover ports from pod spec
				ports, err := discoverPortsFromPodSpec(pod.Pod)
				if err != nil {
					log.Printf("Error discovering ports for pod %s: %v", pod.Name, err)
					ports = []int{}
				}

				for _, ip := range pod.IPs {
					ipResult := scanPQCPodIP(ip, ports, &pod)
					ipResult.OpenshiftComponent = component

					mu.Lock()
					results.IPResults = append(results.IPResults, ipResult)
					results.ScannedIPs++
					mu.Unlock()
				}
			}
		}()
	}

	for _, pod := range allPodsInfo {
		podChan <- pod
	}
	close(podChan)

	wg.Wait()

	return results
}

// scanPQCTarget scans a single host:port target for PQC support
func scanPQCTarget(target string) IPResult {
	parts := strings.Split(target, ":")
	if len(parts) != 2 {
		return IPResult{
			IP:     target,
			Status: "error",
			Error:  "invalid target format (expected host:port)",
		}
	}

	host := parts[0]
	port, err := strconv.Atoi(parts[1])
	if err != nil {
		return IPResult{
			IP:     host,
			Status: "error",
			Error:  fmt.Sprintf("invalid port: %v", err),
		}
	}

	log.Printf("PQC check on %s:%d using testssl.sh", host, port)

	tls13, tlsVersions := checkTLS13WithTestSSL(target)
	mlkemSupported, mlkemKEMs, allKEMs := checkMLKEMWithTestSSL(target)

	portResult := PortResult{
		Port:           port,
		Protocol:       "tcp",
		State:          "open",
		Service:        "https",
		TlsVersions:    tlsVersions,
		TLS13Supported: tls13,
		MLKEMSupported: mlkemSupported,
		MLKEMCiphers:   mlkemKEMs,
		AllKEMs:        allKEMs,
		Status:         StatusOK,
	}

	if tls13 && mlkemSupported {
		portResult.Reason = "TLS 1.3 + ML-KEM supported (PQC ready)"
	} else if tls13 {
		portResult.Reason = "TLS 1.3 supported, ML-KEM not available"
	} else {
		portResult.Reason = "TLS 1.3 not supported"
	}

	return IPResult{
		IP:          host,
		Status:      "scanned",
		OpenPorts:   []int{port},
		PortResults: []PortResult{portResult},
	}
}

func scanPQCPodIP(ip string, ports []int, pod *PodInfo) IPResult {
	ipResult := IPResult{
		IP:          ip,
		Pod:         pod,
		Status:      "scanned",
		OpenPorts:   ports,
		PortResults: make([]PortResult, 0),
	}

	if len(ports) == 0 {
		ipResult.PortResults = append(ipResult.PortResults, PortResult{
			Port:   0,
			Status: StatusNoPorts,
			Reason: "Pod declares no TCP ports in spec",
		})
		return ipResult
	}

	for _, port := range ports {
		target := fmt.Sprintf("%s:%d", ip, port)
		log.Printf("PQC check on pod %s/%s at %s", pod.Namespace, pod.Name, target)

		tls13, tlsVersions := checkTLS13WithTestSSL(target)
		mlkemSupported, mlkemKEMs, allKEMs := checkMLKEMWithTestSSL(target)

		portResult := PortResult{
			Port:           port,
			Protocol:       "tcp",
			State:          "open",
			TlsVersions:    tlsVersions,
			TLS13Supported: tls13,
			MLKEMSupported: mlkemSupported,
			MLKEMCiphers:   mlkemKEMs,
			AllKEMs:        allKEMs,
			Status:         StatusOK,
		}

		if tls13 && mlkemSupported {
			portResult.Reason = "TLS 1.3 + ML-KEM supported (PQC ready)"
		} else if tls13 {
			portResult.Reason = "TLS 1.3 supported, ML-KEM not available"
		} else if len(tlsVersions) > 0 {
			portResult.Reason = "TLS supported, TLS 1.3 not available"
		} else {
			portResult.Reason = "Could not determine TLS support"
			portResult.Status = StatusNoTLS
		}

		ipResult.PortResults = append(ipResult.PortResults, portResult)
	}

	return ipResult
}

func checkTLS13WithTestSSL(target string) (bool, []string) {
	log.Printf("Checking TLS versions with testssl.sh -p for %s", target)

	cmd := exec.Command("testssl.sh",
		"-p",
		"--quiet",
		"--color", "0",
		"--ip", "one",
		target,
	)

	output, err := cmd.CombinedOutput()
	outputStr := string(output)
	log.Printf("testssl.sh -p output for %s:\n%s", target, outputStr)

	if err != nil && len(outputStr) == 0 {
		log.Printf("testssl.sh -p failed for %s: %v", target, err)
		return false, nil
	}

	var versions []string
	tls13 := false

	lines := strings.Split(outputStr, "\n")
	for _, line := range lines {
		lineLower := strings.ToLower(line)

		if strings.Contains(line, "TLS 1.3") && !strings.Contains(lineLower, "not offered") {
			tls13 = true
			if !stringInSlice("TLSv1.3", versions) {
				versions = append(versions, "TLSv1.3")
			}
		}
		if strings.Contains(lineLower, "offered") {
			if strings.Contains(line, "TLS 1.2") {
				if !stringInSlice("TLSv1.2", versions) {
					versions = append(versions, "TLSv1.2")
				}
			}
			if strings.Contains(line, "TLS 1.1") {
				if !stringInSlice("TLSv1.1", versions) {
					versions = append(versions, "TLSv1.1")
				}
			}
			if strings.Contains(line, "TLS 1.0") {
				if !stringInSlice("TLSv1.0", versions) {
					versions = append(versions, "TLSv1.0")
				}
			}
		}
	}

	return tls13, versions
}

func checkMLKEMWithTestSSL(target string) (bool, []string, []string) {
	log.Printf("Checking ML-KEM KEMs with testssl.sh -f for %s", target)

	cmd := exec.Command("testssl.sh",
		"-f",
		"--quiet",
		"--color", "0",
		"--ip", "one",
		target,
	)

	output, err := cmd.CombinedOutput()
	outputStr := string(output)
	log.Printf("testssl.sh -f output for %s:\n%s", target, outputStr)

	if err != nil && len(outputStr) == 0 {
		log.Printf("testssl.sh -f failed for %s: %v", target, err)
		return false, nil, nil
	}

	var mlkemKEMs []string
	var allKEMs []string
	mlkemSupported := false

	lines := strings.Split(outputStr, "\n")
	for _, line := range lines {
		if strings.Contains(line, "KEMs offered") {
			parts := strings.SplitN(line, "KEMs offered", 2)
			if len(parts) == 2 {
				kemsStr := strings.TrimSpace(parts[1])
				kems := strings.Fields(kemsStr)
				for _, kem := range kems {
					kem = strings.TrimSpace(kem)
					if kem == "" {
						continue
					}
					allKEMs = append(allKEMs, kem)

					kemLower := strings.ToLower(kem)
					if strings.Contains(kemLower, "mlkem") {
						mlkemSupported = true
						if !stringInSlice(kem, mlkemKEMs) {
							mlkemKEMs = append(mlkemKEMs, kem)
						}
					}
				}
			}
		}
	}

	return mlkemSupported, mlkemKEMs, allKEMs
}

func printPQCClusterResults(results ScanResults) {
	fmt.Printf("\n========================================\n")
	fmt.Printf("PQC CHECK RESULTS\n")
	fmt.Printf("========================================\n")
	fmt.Printf("Timestamp: %s\n", results.Timestamp)
	fmt.Printf("Total IPs: %d\n", results.TotalIPs)
	fmt.Printf("Scanned:   %d\n", results.ScannedIPs)
	fmt.Printf("\n")

	tls13Count := 0
	mlkemCount := 0
	pqcReadyCount := 0

	for _, ipResult := range results.IPResults {
		fmt.Printf("-----------------------------------------------------\n")
		fmt.Printf("IP: %s\n", ipResult.IP)

		if ipResult.Pod != nil {
			fmt.Printf("Pod: %s/%s\n", ipResult.Pod.Namespace, ipResult.Pod.Name)
		}
		if ipResult.OpenshiftComponent != nil {
			fmt.Printf("Component: %s\n", ipResult.OpenshiftComponent.Component)
		}

		if ipResult.Error != "" {
			fmt.Printf("  Error: %s\n", ipResult.Error)
			continue
		}

		for _, portResult := range ipResult.PortResults {
			if portResult.Status == StatusNoPorts {
				fmt.Printf("  No TCP ports declared\n")
				continue
			}

			fmt.Printf("  Port %d:\n", portResult.Port)

			if portResult.TLS13Supported {
				fmt.Printf("    TLS 1.3:  SUPPORTED\n")
				tls13Count++
			} else {
				fmt.Printf("    TLS 1.3:  NOT SUPPORTED\n")
			}

			if portResult.MLKEMSupported {
				fmt.Printf("    ML-KEM:   SUPPORTED\n")
				fmt.Printf("    ML-KEM KEMs: %s\n", strings.Join(portResult.MLKEMCiphers, ", "))
				mlkemCount++
			} else {
				fmt.Printf("    ML-KEM:   NOT SUPPORTED\n")
			}

			if portResult.TLS13Supported && portResult.MLKEMSupported {
				pqcReadyCount++
			}

			if len(portResult.TlsVersions) > 0 {
				fmt.Printf("    TLS Versions: %s\n", strings.Join(portResult.TlsVersions, ", "))
			}

			if len(portResult.AllKEMs) > 0 {
				fmt.Printf("    All KEMs: %s\n", strings.Join(portResult.AllKEMs, ", "))
			}
		}
	}

	fmt.Printf("\n========================================\n")
	fmt.Printf("SUMMARY\n")
	fmt.Printf("========================================\n")
	fmt.Printf("Total Ports Scanned: %d\n", results.ScannedIPs)
	fmt.Printf("TLS 1.3 Ready:       %d\n", tls13Count)
	fmt.Printf("ML-KEM Ready:        %d\n", mlkemCount)
	fmt.Printf("Fully PQC Ready:     %d (TLS 1.3 + ML-KEM)\n", pqcReadyCount)
	fmt.Printf("========================================\n")
}
