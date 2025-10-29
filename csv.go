package main

import (
	"encoding/csv"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
)

var csvColumns = []string{
	"IP", "Port", "Protocol", "Service", "Pod Name", "Namespace", "Component Name", "Component Maintainer",
	"Process", "TLS Ciphers", "TLS Version",
	"Ingress Configured Profile", "Ingress Configured MinVersion", "Ingress MinVersion Compliance", "Ingress Configured Ciphers", "Ingress Cipher Compliance",
	"API Configured Profile", "API Configured MinVersion", "API MinVersion Compliance", "API Configured Ciphers", "API Cipher Compliance",
	"Kubelet Configured MinVersion", "Kubelet MinVersion Compliance", "Kubelet Configured Ciphers", "Kubelet Cipher Compliance",
}

// writeCSVOutput writes scan results to a CSV file with one row per IP/port combination
func writeCSVOutput(results ScanResults, filename string) error {
	log.Printf("Writing CSV output to: %s", filename)

	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create CSV file: %v", err)
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// Write header
	if err := writer.Write(csvColumns); err != nil {
		return fmt.Errorf("failed to write CSV header: %v", err)
	}

	rowCount := 0

	// Defensive checks for nil TLSSecurityConfig
	// TODO initialize these values in the results struct to avoid this mess.
	var ingressProfile, ingressMinVersion, ingressCiphers string
	var apiProfile, apiMinVersion, apiCiphers string
	var kubeletMinVersion, kubeletCiphers string
	if results.TLSSecurityConfig != nil {
		if results.TLSSecurityConfig.IngressController != nil {
			ingressProfile = stringOrNA(results.TLSSecurityConfig.IngressController.Type)
			ingressMinVersion = stringOrNA(results.TLSSecurityConfig.IngressController.MinTLSVersion)
			ingressCiphers = joinOrNA(removeDuplicates(results.TLSSecurityConfig.IngressController.Ciphers))
		} else {
			ingressProfile = "N/A"
			ingressMinVersion = "N/A"
			ingressCiphers = "N/A"
		}
		if results.TLSSecurityConfig.APIServer != nil {
			apiProfile = stringOrNA(results.TLSSecurityConfig.APIServer.Type)
			apiMinVersion = stringOrNA(results.TLSSecurityConfig.APIServer.MinTLSVersion)
			apiCiphers = joinOrNA(removeDuplicates(results.TLSSecurityConfig.APIServer.Ciphers))
		} else {
			apiProfile = "N/A"
			apiMinVersion = "N/A"
			apiCiphers = "N/A"
		}
		if results.TLSSecurityConfig.KubeletConfig != nil {
			kubeletMinVersion = stringOrNA(results.TLSSecurityConfig.KubeletConfig.MinTLSVersion)
			kubeletCiphers = joinOrNA(removeDuplicates(results.TLSSecurityConfig.KubeletConfig.TLSCipherSuites))
		} else {
			kubeletMinVersion = "N/A"
			kubeletCiphers = "N/A"
		}
	} else {
		ingressProfile = "N/A"
		ingressMinVersion = "N/A"
		ingressCiphers = "N/A"
		apiProfile = "N/A"
		apiMinVersion = "N/A"
		apiCiphers = "N/A"
		kubeletMinVersion = "N/A"
		kubeletCiphers = "N/A"
	}

	// Write data rows - one row per IP/port combination
	for _, ipResult := range results.IPResults {
		ipAddress := ipResult.IP

		// Process each port result
		for _, portResult := range ipResult.PortResults {
			targetPort := portResult.Port

			port := strconv.Itoa(targetPort)

			// Create row data
			podName := "N/A"
			namespace := "N/A"
			if ipResult.Pod != nil {
				podName = ipResult.Pod.Name
				namespace = ipResult.Pod.Namespace
			}

			componentName := "N/A"
			componentMaintainer := "N/A"
			if ipResult.OpenshiftComponent != nil {
				componentName = ipResult.OpenshiftComponent.Component
				componentMaintainer = ipResult.OpenshiftComponent.MaintainerComponent
			}

			rowData := map[string]string{
				"IP":                            ipAddress,
				"Port":                          port,
				"Protocol":                      stringOrNA(portResult.Protocol),
				"Service":                       stringOrNA(portResult.Service),
				"Pod Name":                      podName,
				"Namespace":                     namespace,
				"Component Name":                componentName,
				"Component Maintainer":          componentMaintainer,
				"Process":                       stringOrNA(portResult.ProcessName),
				"TLS Ciphers":                   joinOrNA(portResult.TlsCiphers),
				"TLS Version":                   joinOrNA(portResult.TlsVersions),
				"Ingress Configured Profile":    ingressProfile,
				"Ingress Configured MinVersion": ingressMinVersion,
				"Ingress MinVersion Compliance": strconv.FormatBool(portResult.IngressTLSConfigCompliance.Version),
				"Ingress Configured Ciphers":    ingressCiphers,
				"Ingress Cipher Compliance":     strconv.FormatBool(portResult.IngressTLSConfigCompliance.Ciphers),
				"API Configured Profile":        apiProfile,
				"API Configured MinVersion":     apiMinVersion,
				"API MinVersion Compliance":     strconv.FormatBool(portResult.APIServerTLSConfigCompliance.Version),
				"API Configured Ciphers":        apiCiphers,
				"API Cipher Compliance":         strconv.FormatBool(portResult.APIServerTLSConfigCompliance.Ciphers),
				"Kubelet Configured MinVersion": kubeletMinVersion,
				"Kubelet MinVersion Compliance": strconv.FormatBool(portResult.KubeletTLSConfigCompliance.Version),
				"Kubelet Configured Ciphers":    kubeletCiphers,
				"Kubelet Cipher Compliance":     strconv.FormatBool(portResult.KubeletTLSConfigCompliance.Ciphers),
			}

			row := buildCSVRow(csvColumns, rowData)
			if err := writer.Write(row); err != nil {
				return fmt.Errorf("failed to write CSV row: %v", err)
			}
			rowCount++
		}

	}

	return nil
}

// writeScanErrorsCSV writes scan errors to a CSV file
func writeScanErrorsCSV(results ScanResults, filename string) error {
	if len(results.ScanErrors) == 0 {
		log.Printf("No scan errors to write to CSV file")
		return nil
	}

	log.Printf("Writing scan errors to: %s", filename)

	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create scan errors CSV file: %v", err)
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// Write header
	header := []string{"IP", "Port", "Error Type", "Error Message", "Pod Name", "Namespace", "Container"}
	if err := writer.Write(header); err != nil {
		return fmt.Errorf("failed to write scan errors CSV header: %v", err)
	}

	// Write error rows
	for _, scanError := range results.ScanErrors {
		row := []string{
			scanError.IP,
			strconv.Itoa(scanError.Port),
			scanError.ErrorType,
			scanError.ErrorMsg,
			stringOrNA(scanError.PodName),
			stringOrNA(scanError.Namespace),
			stringOrNA(scanError.Container),
		}

		if err := writer.Write(row); err != nil {
			return fmt.Errorf("failed to write scan error row: %v", err)
		}
	}

	log.Printf("Successfully wrote %d scan error rows to CSV file", len(results.ScanErrors))
	return nil
}

// Helper function to build CSV row based on selected columns
func buildCSVRow(selectedColumns []string, data map[string]string) []string {
	row := make([]string, len(selectedColumns))
	for i, col := range selectedColumns {
		if value, exists := data[col]; exists {
			row[i] = value
		} else {
			row[i] = "N/A"
		}
	}
	return row
}

// Helper functions
func stringOrNA(s string) string {
	if s == "" {
		return "N/A"
	}
	return s
}

func joinOrNA(slice []string) string {
	if len(slice) == 0 {
		return "N/A"
	}
	return strings.Join(slice, ", ")
}

// Helper function to remove duplicates from string slice
func removeDuplicates(slice []string) []string {
	keys := make(map[string]bool)
	var result []string
	for _, item := range slice {
		if !keys[item] && item != "" {
			keys[item] = true
			result = append(result, item)
		}
	}
	return result
}
