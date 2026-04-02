package output

import (
	"fmt"
	"log"
	"strings"

	"github.com/openshift/tls-scanner/internal/scanner"
)

func PrintClusterResults(results scanner.ScanResults) {
	fmt.Printf("=== CLUSTER SCAN RESULTS ===\n")
	fmt.Printf("Timestamp: %s\n", results.Timestamp)
	fmt.Printf("Total IPs: %d\n", results.TotalIPs)
	fmt.Printf("Successfully Scanned: %d\n", results.ScannedIPs)
	fmt.Printf("\n")

	for _, ipResult := range results.IPResults {
		fmt.Printf("-----------------------------------------------------\n")
		fmt.Printf("IP: %s\n", ipResult.IP)
		if ipResult.OpenshiftComponent != nil {
			fmt.Printf("Component: %s\n", ipResult.OpenshiftComponent.Component)
			fmt.Printf("Source Location: %s\n", ipResult.OpenshiftComponent.SourceLocation)
			fmt.Printf("Maintainer: %s\n", ipResult.OpenshiftComponent.MaintainerComponent)
			fmt.Printf("Is Bundle: %t\n", ipResult.OpenshiftComponent.IsBundle)
		}
		if len(ipResult.Services) > 0 {
			fmt.Printf("Services:\n")
			for _, service := range ipResult.Services {
				fmt.Printf("  - %s/%s (Type: %s", service.Namespace, service.Name, service.Type)
				if len(service.Ports) > 0 {
					fmt.Printf(", Ports: %v", service.Ports)
				}
				fmt.Printf(")\n")
			}
		}
		fmt.Printf("Status: %s\n", ipResult.Status)

		if ipResult.Error != "" {
			fmt.Printf("Error: %s\n", ipResult.Error)
			continue
		}

		if len(ipResult.OpenPorts) == 0 {
			fmt.Printf("No open ports found\n")
			continue
		}

		fmt.Printf("Open Ports: %v\n", ipResult.OpenPorts)
		fmt.Printf("\n")

		for _, portResult := range ipResult.PortResults {
			fmt.Printf("  Port %d:\n", portResult.Port)
			if portResult.Error != "" {
				fmt.Printf("    Error: %s\n", portResult.Error)
				continue
			}

			fmt.Printf("    Protocol: %s\n", portResult.Protocol)
			fmt.Printf("    State: %s\n", portResult.State)
			fmt.Printf("    Service: %s\n", portResult.Service)
			if portResult.ProcessName != "" {
				fmt.Printf("    Process Name: %s (%s)\n", portResult.ProcessName, portResult.ContainerName)
			}

			if len(portResult.TlsVersions) > 0 {
				fmt.Printf("    TLS Versions: %s\n", strings.Join(portResult.TlsVersions, ", "))
			}
			if len(portResult.TlsCiphers) > 0 {
				fmt.Printf("    Ciphers:\n")
				for _, cipher := range portResult.TlsCiphers {
					fmt.Printf("      %s\n", cipher)
				}
			}
			fmt.Printf("\n")
		}
	}
}

func PrintParsedResults(results scanner.ScanResults) {
	if len(results.IPResults) == 0 {
		log.Println("No hosts were scanned or host is down.")
		return
	}

	for _, ipResult := range results.IPResults {
		for _, portResult := range ipResult.PortResults {
			fmt.Printf("PORT    STATE SERVICE REASON\n")
			fmt.Printf("%d/%s %-5s %-7s %s\n", portResult.Port, portResult.Protocol, portResult.State, portResult.Service, portResult.Reason)

			if len(portResult.TlsVersions) > 0 || len(portResult.TlsCiphers) > 0 {
				fmt.Println("| ssl-enum-ciphers:")
				for _, version := range portResult.TlsVersions {
					fmt.Printf("|   %s:\n", version)
				}
			if len(portResult.TlsCiphers) > 0 {
				fmt.Printf("|   ciphers:\n")
				for _, cipher := range portResult.TlsCiphers {
					fmt.Printf("|     %s\n", cipher)
				}
			}
			}
		}
	}
}

func PrintPQCClusterResults(results scanner.ScanResults) {
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
			if portResult.Status == scanner.StatusNoPorts {
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
