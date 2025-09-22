package main

import (
	"encoding/xml"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

func main() {
	host := flag.String("host", "127.0.0.1", "The target host or IP address to scan")
	port := flag.String("port", "443", "The target port to scan")
	jsonOutput := flag.String("json", "", "Output results in JSON format to specified file (if empty, outputs to stdout in human-readable format)")
	csvOutput := flag.String("csv", "", "Output results in CSV format to specified file")
	concurrentScans := flag.Int("j", 1, "Number of concurrent scans to run in parallel (speeds up large IP lists significantly!)")
	allPods := flag.Bool("all-pods", false, "Scan all pods in the current namespace (overrides --iplist and --host)")
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

		if *csvOutput != "" {
			scanResults = performClusterScan(allPodsInfo, *concurrentScans, k8sClient)

			// Write JSON if also requested
			if *jsonOutput != "" {
				// Convert ScanResults to JSON format
				if err := writeJSONOutput(scanResults, *jsonOutput); err != nil {
					log.Printf("Error writing JSON output: %v", err)
				} else {
					log.Printf("JSON results written to: %s", *jsonOutput)
				}
			}

			// Write CSV output
			if err := writeCSVOutput(scanResults, *csvOutput); err != nil {
				log.Printf("Error writing CSV output: %v", err)
			} else {
				log.Printf("CSV results written to: %s", *csvOutput)
			}

			// Write scan errors CSV if there are any errors
			if len(scanResults.ScanErrors) > 0 {
				errorFilename := strings.TrimSuffix(*csvOutput, filepath.Ext(*csvOutput)) + "_errors.csv"
				if err := writeScanErrorsCSV(scanResults, errorFilename); err != nil {
					log.Printf("Error writing scan errors CSV: %v", err)
				} else {
					log.Printf("Scan errors written to: %s", errorFilename)
				}
			}

			// Print to console if no output files specified
			if *jsonOutput == "" {
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

	cmd := exec.Command("nmap", "-sV", "--script", "ssl-enum-ciphers", "-p", *port, "-oX", "-", *host)

	output, err := cmd.CombinedOutput() // CombinedOutput captures both stdout and stderr.
	if err != nil {
		log.Fatalf("Error executing Nmap command. Nmap output:\n%s", string(output))
	}

	var nmapResult NmapRun
	if err := xml.Unmarshal(output, &nmapResult); err != nil {
		log.Fatalf("Error parsing Nmap XML output: %v", err)
	}

	if *jsonOutput != "" {
		if err := writeJSONOutput(nmapResult, *jsonOutput); err != nil {
			log.Fatalf("Error writing JSON output: %v", err)
		}
		log.Printf("JSON results written to %s", *jsonOutput)
	}

	if *csvOutput != "" {
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

		if err := writeCSVOutput(singleResult, *csvOutput); err != nil {
			log.Fatalf("Error writing CSV output: %v", err)
		}
		log.Printf("CSV results written to %s", *csvOutput)

		// Write scan errors CSV if there are any errors
		if len(singleResult.ScanErrors) > 0 {
			errorFilename := strings.TrimSuffix(*csvOutput, filepath.Ext(*csvOutput)) + "_errors.csv"
			if err := writeScanErrorsCSV(singleResult, errorFilename); err != nil {
				log.Printf("Error writing scan errors CSV: %v", err)
			} else {
				log.Printf("Scan errors written to: %s", errorFilename)
			}
		}
	}

	if *jsonOutput == "" && *csvOutput == "" {
		printParsedResults(nmapResult)
	}
}

func isNmapInstalled() bool {
	_, err := exec.LookPath("nmap")
	return err == nil
}

func discoverOpenPorts(ip string) ([]int, error) {
	log.Printf("Discovering open ports for %s...", ip)

	// We scan all ports for this ip first to get the open ports
	// for constructing the final results.
	cmd := exec.Command("nmap", "-p-", "--open", "-T4", ip)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("nmap port discovery failed: %v", err)
	}

	re := regexp.MustCompile(`^(\d+)/tcp\s+open`)
	var ports []int

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		matches := re.FindStringSubmatch(strings.TrimSpace(line))
		if len(matches) > 1 {
			if port, err := strconv.Atoi(matches[1]); err == nil {
				ports = append(ports, port)
			}
		}
	}

	log.Printf("Found %d open ports for %s: %v", len(ports), ip, ports)
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
	// TODO nmap prints some ciphersuites to specify that an "authenticated key exchange", AKE was used
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
	openPorts, err := discoverOpenPorts(ip)
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

	log.Printf("Scanning %d SSL ciphers on %s for ports: %s", len(openPorts), ip, portSpec)
	cmd := exec.Command("nmap", "-sV", "--script", "ssl-enum-ciphers", "-p", portSpec, "-oX", "-", ip)
	output, err := cmd.CombinedOutput()
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
