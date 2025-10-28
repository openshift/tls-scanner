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
	host := flag.String("host", "127.0.0.1", "The target host or IP address to scan")
	port := flag.String("port", "443", "The target port to scan")
	artifactDir := flag.String("artifact-dir", "/tmp", "Directory to save the artifacts to")
	jsonFile := flag.String("json-file", "", "Output results in JSON format to specified file in artifact-dir")
	csvFile := flag.String("csv-file", "", "Output results in CSV format to specified file in artifact-dir")
	junitFile := flag.String("junit-file", "", "Output results in JUnit XML format to specified file in artifact-dir")
	concurrentScans := flag.Int("j", 1, "Number of concurrent scans to run in parallel (speeds up large IP lists significantly!)")
	allPods := flag.Bool("all-pods", false, "Scan all pods in the current namespace (overrides --iplist and --host)")
	targets := flag.String("targets", "", "A comma-separated list of host:port targets to scan")
	limitIPs := flag.Int("limit-ips", 0, "Limit the number of IPs to scan for testing purposes (0 = no limit)")
	logFile := flag.String("log-file", "", "Redirect all log output to the specified file")
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

	// Validate concurrent scans parameter
	if *concurrentScans < 1 {
		log.Fatal("Error: Number of concurrent scans must be at least 1")
	}

	var k8sClient *K8sClient
	var err error
	var allPodsInfo []PodInfo

	if *targets != "" {
		targetList := strings.Split(*targets, ",")
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

		scanResults := performTargetsScan(targetsByHost, *concurrentScans)

		// Create artifact directory if it doesn't exist
		if *csvFile != "" || *jsonFile != "" || *junitFile != "" {
			if err := os.MkdirAll(*artifactDir, 0755); err != nil {
				log.Fatalf("Could not create artifact directory %s: %v", *artifactDir, err)
			}
			log.Printf("Artifacts will be saved to: %s", *artifactDir)
		}

		// Write JSON if also requested
		if *jsonFile != "" {
			jsonPath := *jsonFile
			if !filepath.IsAbs(jsonPath) {
				jsonPath = filepath.Join(*artifactDir, *jsonFile)
			}
			if err := writeJSONOutput(scanResults, jsonPath); err != nil {
				log.Printf("Error writing JSON output: %v", err)
			} else {
				log.Printf("JSON results written to: %s", jsonPath)
			}
		}

		// Write CSV output
		if *csvFile != "" {
			csvPath := *csvFile
			if !filepath.IsAbs(csvPath) {
				csvPath = filepath.Join(*artifactDir, *csvFile)
			}
			if err := writeCSVOutput(scanResults, csvPath); err != nil {
				log.Printf("Error writing CSV output: %v", err)
			} else {
				log.Printf("CSV results written to: %s", csvPath)
			}
		}
		// Write JUnit XML output
		if *junitFile != "" {
			junitPath := *junitFile
			if !filepath.IsAbs(junitPath) {
				junitPath = filepath.Join(*artifactDir, *junitFile)
			}
			if err := writeJUnitOutput(scanResults, junitPath); err != nil {
				log.Printf("Error writing JUnit XML output: %v", err)
			} else {
				log.Printf("JUnit XML results written to: %s", junitPath)
			}
		}

		// Print to console if no output files specified
		if *jsonFile == "" && *csvFile == "" && *junitFile == "" {
			printClusterResults(scanResults)
		}

		return
	}

	if *allPods {
		k8sClient, err = newK8sClient()
		if err != nil {
			log.Fatalf("Could not create kubernetes client for --all-pods: %v", err)
		}

		allPodsInfo = k8sClient.getAllPodsInfo() // get pod ip to pod name mapping

		log.Printf("Found %d pods to scan from the cluster.", len(allPodsInfo))

		// Apply IP limit if specified
		if *limitIPs > 0 {
			totalIPs := 0
			for _, pod := range allPodsInfo {
				totalIPs += len(pod.IPs)
			}

			if totalIPs > *limitIPs {
				log.Printf("Limiting scan to %d IPs (found %d total IPs)", *limitIPs, totalIPs)
				allPodsInfo = limitPodsToIPCount(allPodsInfo, *limitIPs)
				limitedTotal := 0
				for _, pod := range allPodsInfo {
					limitedTotal += len(pod.IPs)
				}
				log.Printf("After limiting: %d pods with %d total IPs", len(allPodsInfo), limitedTotal)
			}
		}
	}

	if len(allPodsInfo) > 0 {
		var scanResults ScanResults

		if *csvFile != "" || *jsonFile != "" || *junitFile != "" {
			scanResults = performClusterScan(allPodsInfo, *concurrentScans, k8sClient)

			// Create artifact directory if it doesn't exist
			if err := os.MkdirAll(*artifactDir, 0755); err != nil {
				log.Fatalf("Could not create artifact directory %s: %v", *artifactDir, err)
			}
			log.Printf("Artifacts will be saved to: %s", *artifactDir)

			// Write JSON if also requested
			if *jsonFile != "" {
				jsonPath := *jsonFile
				if !filepath.IsAbs(jsonPath) {
					jsonPath = filepath.Join(*artifactDir, *jsonFile)
				}
				if err := writeJSONOutput(scanResults, jsonPath); err != nil {
					log.Printf("Error writing JSON output: %v", err)
				} else {
					log.Printf("JSON results written to: %s", jsonPath)
				}
			}

			// Write CSV output
			if *csvFile != "" {
				csvPath := *csvFile
				if !filepath.IsAbs(csvPath) {
					csvPath = filepath.Join(*artifactDir, *csvFile)
				}
				if err := writeCSVOutput(scanResults, csvPath); err != nil {
					log.Printf("Error writing CSV output: %v", err)
				} else {
					log.Printf("CSV results written to: %s", csvPath)
				}

				// Write scan errors CSV if there are any errors
				if len(scanResults.ScanErrors) > 0 {
					errorFilename := strings.TrimSuffix(csvPath, filepath.Ext(csvPath)) + "_errors.csv"
					if err := writeScanErrorsCSV(scanResults, errorFilename); err != nil {
						log.Printf("Error writing scan errors CSV: %v", err)
					} else {
						log.Printf("Scan errors written to: %s", errorFilename)
					}
				}
			}
			// Write JUnit XML output
			if *junitFile != "" {
				junitPath := *junitFile
				if !filepath.IsAbs(junitPath) {
					junitPath = filepath.Join(*artifactDir, *junitFile)
				}
				if err := writeJUnitOutput(scanResults, junitPath); err != nil {
					log.Printf("Error writing JUnit XML output: %v", err)
				} else {
					log.Printf("JUnit XML results written to: %s", junitPath)
				}
			}

			// Print to console if no output files specified
			if *jsonFile == "" {
				printClusterResults(scanResults)
			}
		} else {
			// Console output only
			scanResults = performClusterScan(allPodsInfo, *concurrentScans, k8sClient)
			printClusterResults(scanResults)
		}

		return
	}

	log.Printf("Found Nmap. Starting scan on %s:%s...\n\n", *host, *port)

	cmd := exec.Command("nmap", "-Pn", "-sV", "--script", "ssl-enum-ciphers", "-p", *port, "-oX", "-", *host)

	output, err := cmd.CombinedOutput() // CombinedOutput captures both stdout and stderr.
	if err != nil {
		log.Fatalf("Error executing Nmap command. Nmap output:\n%s", string(output))
	}

	var nmapResult NmapRun
	if err := xml.Unmarshal(output, &nmapResult); err != nil {
		log.Fatalf("Error parsing Nmap XML output: %v", err)
	}

	if *jsonFile != "" {
		jsonPath := *jsonFile
		if !filepath.IsAbs(jsonPath) {
			jsonPath = filepath.Join(*artifactDir, *jsonFile)
		}
		if err := writeJSONOutput(nmapResult, jsonPath); err != nil {
			log.Fatalf("Error writing JSON output: %v", err)
		}
		log.Printf("JSON results written to %s", jsonPath)
	}

	if *csvFile != "" {
		csvPath := *csvFile
		if !filepath.IsAbs(csvPath) {
			csvPath = filepath.Join(*artifactDir, *csvFile)
		}
		// For single host scans, try to get TLS config if k8s client is available
		var tlsConfig *TLSSecurityProfile
		if k8sClient != nil {
			if config, err := k8sClient.getTLSSecurityProfile(); err != nil {
				log.Printf("Warning: Could not collect TLS security profiles: %v", err)
			} else {
				tlsConfig = config
			}
		}

		// Convert single scan to ScanResults format for CSV
		singleResult := ScanResults{
			Timestamp:         time.Now().Format(time.RFC3339),
			TotalIPs:          1,
			ScannedIPs:        1,
			TLSSecurityConfig: tlsConfig,
			IPResults: []IPResult{{
				IP:          *host,
				Status:      "scanned",
				OpenPorts:   []int{}, // Will be extracted from nmapResult
				PortResults: []PortResult{},
			}},
		}

		// Extract port information from nmap result
		if len(nmapResult.Hosts) > 0 && len(nmapResult.Hosts[0].Ports) > 0 {
			for _, nmapPort := range nmapResult.Hosts[0].Ports {
				if port, err := strconv.Atoi(nmapPort.PortID); err == nil {
					singleResult.IPResults[0].OpenPorts = append(singleResult.IPResults[0].OpenPorts, port)
					singleResult.IPResults[0].PortResults = append(singleResult.IPResults[0].PortResults, PortResult{
						Port:     port,
						Protocol: nmapPort.Protocol,
						State:    nmapPort.State.State,
						Service:  nmapPort.Service.Name,
						NmapRun:  nmapResult,
					})
				}
			}
		}

		if err := writeCSVOutput(singleResult, csvPath); err != nil {
			log.Fatalf("Error writing CSV output: %v", err)
		}
		log.Printf("CSV results written to %s", csvPath)

		// Write scan errors CSV if there are any errors
		if len(singleResult.ScanErrors) > 0 {
			errorFilename := strings.TrimSuffix(csvPath, filepath.Ext(csvPath)) + "_errors.csv"
			if err := writeScanErrorsCSV(singleResult, errorFilename); err != nil {
				log.Printf("Error writing scan errors CSV: %v", err)
			} else {
				log.Printf("Scan errors written to: %s", errorFilename)
			}
		}
	}

	if *jsonFile == "" && *csvFile == "" {
		printParsedResults(nmapResult)
	}
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

func extractTLSInfo(nmapRun NmapRun) (versions []string, ciphers []string, cipherStrength map[string]string) {
	// Collect all detected ciphers and TLS versions for this port
	var allDetectedCiphers []string
	var tlsVersions []string
	cipherStrength = make(map[string]string) // TODO currently unused. Might be useful

	// Extract TLS versions and ciphers from nmap script results
	for _, host := range nmapRun.Hosts {
		for _, nmapPort := range host.Ports {
			for _, script := range nmapPort.Scripts {
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
		}
	}

	ipResult := IPResult{
		IP:          ip,
		Pod:         &pod,
		Status:      "scanned",
		OpenPorts:   openPorts,
		PortResults: make([]PortResult, 0, len(openPorts)),
	}

	// Convert port numbers to a comma-separated string for nmap
	portStrings := make([]string, len(openPorts))
	for i, p := range openPorts {
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
		for _, port := range openPorts {
			ipResult.PortResults = append(ipResult.PortResults, PortResult{Port: port, Error: "nmap scan failed"})
		}
		return ipResult
	}

	var nmapResult NmapRun
	if err := xml.Unmarshal(output, &nmapResult); err != nil {
		ipResult.Error = fmt.Sprintf("failed to parse nmap XML: %v", err)
		for _, port := range openPorts {
			ipResult.PortResults = append(ipResult.PortResults, PortResult{Port: port, Error: "nmap xml parse failed"})
		}
		return ipResult
	}

	// Create a map of port results from the single nmap run
	resultsByPort := make(map[string]PortResult)
	if len(nmapResult.Hosts) > 0 {
		for _, nmapPort := range nmapResult.Hosts[0].Ports {
			portNum, _ := strconv.Atoi(nmapPort.PortID)
			portResult := PortResult{
				Port:     portNum,
				Protocol: nmapPort.Protocol,
				State:    nmapPort.State.State,
				Service:  nmapPort.Service.Name,
				NmapRun:  NmapRun{Hosts: []Host{{Ports: []Port{nmapPort}}}},
			}
			portResult.TlsVersions, portResult.TlsCiphers, portResult.TlsCipherStrength = extractTLSInfo(portResult.NmapRun)
			resultsByPort[nmapPort.PortID] = portResult
		}
	}

	// Correlate results with discovered ports
	for _, port := range openPorts {
		if portResult, ok := resultsByPort[strconv.Itoa(port)]; ok {
			// Check compliance and get process info if TLS data was found
			if len(portResult.TlsCiphers) > 0 {
				checkCompliance(&portResult, tlsSecurityProfile)

				if k8sClient != nil && len(pod.Containers) > 0 {
					k8sClient.getAndCachePodProcesses(pod)
					k8sClient.processCacheMutex.Lock()
					if processName, ok := k8sClient.processNameMap[ip][port]; ok {
						portResult.ProcessName = processName
						portResult.ContainerName = strings.Join(pod.Containers, ",")
					}
					k8sClient.processCacheMutex.Unlock()
				}
			}
			ipResult.PortResults = append(ipResult.PortResults, portResult)
		} else {
			// Port was discovered but not in the ssl-enum-ciphers result (e.g., not an SSL port)
			ipResult.PortResults = append(ipResult.PortResults, PortResult{Port: port, State: "open"})
		}
	}

	return ipResult
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
			ipResult.PortResults = append(ipResult.PortResults, PortResult{Port: port, Error: "nmap scan failed"})
		}
		return ipResult
	}

	var nmapResult NmapRun
	if err := xml.Unmarshal(output, &nmapResult); err != nil {
		ipResult.Error = fmt.Sprintf("failed to parse nmap XML: %v", err)
		for _, portStr := range ports {
			port, _ := strconv.Atoi(portStr)
			ipResult.PortResults = append(ipResult.PortResults, PortResult{Port: port, Error: "nmap xml parse failed"})
		}
		return ipResult
	}

	resultsByPort := make(map[string]PortResult)
	if len(nmapResult.Hosts) > 0 {
		for _, nmapPort := range nmapResult.Hosts[0].Ports {
			portNum, _ := strconv.Atoi(nmapPort.PortID)
			portResult := PortResult{
				Port:     portNum,
				Protocol: nmapPort.Protocol,
				State:    nmapPort.State.State,
				Service:  nmapPort.Service.Name,
				NmapRun:  NmapRun{Hosts: []Host{{Ports: []Port{nmapPort}}}},
			}
			portResult.TlsVersions, portResult.TlsCiphers, portResult.TlsCipherStrength = extractTLSInfo(portResult.NmapRun)
			resultsByPort[nmapPort.PortID] = portResult
		}
	}

	for _, portStr := range ports {
		port, _ := strconv.Atoi(portStr)
		if portResult, ok := resultsByPort[portStr]; ok {
			ipResult.PortResults = append(ipResult.PortResults, portResult)
		} else {
			// Port was specified but not in the result (e.g., not an SSL port or closed)
			ipResult.PortResults = append(ipResult.PortResults, PortResult{Port: port, State: "closed/filtered"})
		}
	}

	return ipResult
}

