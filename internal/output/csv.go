package output

import (
	"encoding/csv"
	"fmt"
	"log/slog"
	"os"
	"slices"
	"strconv"
	"strings"

	"github.com/openshift/tls-scanner/internal/scanner"
	"github.com/openshift/tls-scanner/internal/stringutil"
)

var csvColumns = []string{
	"IP", "Port", "Protocol", "Service", "STARTTLS Protocol", "Pod Name", "Namespace", "Component Name", "Component Maintainer",
	"Process", "TLS Ciphers", "TLS Version", "TLS Supported Groups", "Cert Signature Algorithms", "Status", "Reason", "Listen Address",
	"TLS 1.3 Supported", "ML-KEM Supported", "ML-KEM KEMs", "All KEMs",
	"TLS 1.3 Offered", "TLS 1.2 Only", "PQC Capable", "Readiness Notes",
	"Ingress Configured Profile", "Ingress Configured MinVersion", "Ingress MinVersion Compliance", "Ingress Configured Ciphers", "Ingress Cipher Compliance",
	"API Configured Profile", "API Configured MinVersion", "API MinVersion Compliance", "API Configured Ciphers", "API Cipher Compliance",
	"Kubelet Configured MinVersion", "Kubelet MinVersion Compliance", "Kubelet Configured Ciphers", "Kubelet Cipher Compliance",
}

func WriteCSVOutput(results scanner.ScanResults, filename string) error {
	slog.Info("writing CSV output", "path", filename)

	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create CSV file: %w", err)
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	if err := writer.Write(csvColumns); err != nil {
		return fmt.Errorf("failed to write CSV header: %w", err)
	}

	rowCount := 0

	var ingressProfile, ingressMinVersion, ingressCiphers string
	var apiProfile, apiMinVersion, apiCiphers string
	var kubeletMinVersion, kubeletCiphers string
	if results.TLSSecurityConfig != nil {
		if results.TLSSecurityConfig.IngressController != nil {
			ingressProfile = stringOrNA(results.TLSSecurityConfig.IngressController.Type)
			ingressMinVersion = stringOrNA(results.TLSSecurityConfig.IngressController.MinTLSVersion)
			ingressCiphers = joinOrNA(stringutil.RemoveDuplicates(results.TLSSecurityConfig.IngressController.Ciphers))
		} else {
			ingressProfile = "N/A"
			ingressMinVersion = "N/A"
			ingressCiphers = "N/A"
		}
		if results.TLSSecurityConfig.APIServer != nil {
			apiProfile = stringOrNA(results.TLSSecurityConfig.APIServer.Type)
			apiMinVersion = stringOrNA(results.TLSSecurityConfig.APIServer.MinTLSVersion)
			apiCiphers = joinOrNA(stringutil.RemoveDuplicates(results.TLSSecurityConfig.APIServer.Ciphers))
		} else {
			apiProfile = "N/A"
			apiMinVersion = "N/A"
			apiCiphers = "N/A"
		}
		if results.TLSSecurityConfig.KubeletConfig != nil {
			kubeletMinVersion = stringOrNA(results.TLSSecurityConfig.KubeletConfig.MinTLSVersion)
			kubeletCiphers = joinOrNA(stringutil.RemoveDuplicates(results.TLSSecurityConfig.KubeletConfig.TLSCipherSuites))
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

	for _, ipResult := range results.IPResults {
		ipAddress := ipResult.IP

		for _, portResult := range ipResult.PortResults {
			port := strconv.Itoa(portResult.Port)

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

			statusStr := "N/A"
			if portResult.Status != "" {
				statusStr = string(portResult.Status)
			}

			supportedGroups := "N/A"
			if portResult.TlsKeyExchange != nil {
				allGroups := append([]string{}, portResult.TlsKeyExchange.Groups...)
				if portResult.TlsKeyExchange.ForwardSecrecy != nil {
					for _, kem := range portResult.TlsKeyExchange.ForwardSecrecy.KEMs {
						if !slices.Contains(allGroups, kem) {
							allGroups = append(allGroups, kem)
						}
					}
				}
				supportedGroups = joinOrNA(allGroups)
			}

			rowData := map[string]string{
				"IP":                            ipAddress,
				"Port":                          port,
				"Protocol":                      stringOrNA(portResult.Protocol),
				"Service":                       stringOrNA(portResult.Service),
				"STARTTLS Protocol":             stringOrNA(portResult.STARTTLSProtocol),
				"Pod Name":                      podName,
				"Namespace":                     namespace,
				"Component Name":                componentName,
				"Component Maintainer":          componentMaintainer,
				"Process":                       stringOrNA(portResult.ProcessName),
				"TLS Ciphers":                   joinOrNA(portResult.TlsCiphers),
				"TLS Version":                   joinOrNA(portResult.TlsVersions),
				"TLS Supported Groups":          supportedGroups,
				"Cert Signature Algorithms":     joinOrNA(portResult.TlsCertSignatureAlgorithms),
				"Status":                        statusStr,
				"Reason":                        stringOrNA(portResult.Reason),
				"Listen Address":                stringOrNA(portResult.ListenAddress),
				"TLS 1.3 Supported":             boolToYesNo(portResult.TLS13Supported),
				"ML-KEM Supported":              boolToYesNo(portResult.MLKEMSupported),
				"ML-KEM KEMs":                   joinOrNA(portResult.MLKEMCiphers),
				"All KEMs":                      joinOrNA(portResult.AllKEMs),
				"TLS 1.3 Offered":               "No",
				"TLS 1.2 Only":                  "No",
				"PQC Capable":                   "No",
				"Readiness Notes":               "N/A",
				"Ingress Configured Profile":    ingressProfile,
				"Ingress Configured MinVersion": ingressMinVersion,
				"Ingress MinVersion Compliance": "N/A",
				"Ingress Configured Ciphers":    ingressCiphers,
				"Ingress Cipher Compliance":     "N/A",
				"API Configured Profile":        apiProfile,
				"API Configured MinVersion":     apiMinVersion,
				"API MinVersion Compliance":     "N/A",
				"API Configured Ciphers":        apiCiphers,
				"API Cipher Compliance":         "N/A",
				"Kubelet Configured MinVersion": kubeletMinVersion,
				"Kubelet MinVersion Compliance": "N/A",
				"Kubelet Configured Ciphers":    kubeletCiphers,
				"Kubelet Cipher Compliance":     "N/A",
			}

			if portResult.IngressTLSConfigCompliance != nil {
				rowData["Ingress MinVersion Compliance"] = strconv.FormatBool(portResult.IngressTLSConfigCompliance.Version)
				rowData["Ingress Cipher Compliance"] = strconv.FormatBool(portResult.IngressTLSConfigCompliance.Ciphers)
			}
			if portResult.APIServerTLSConfigCompliance != nil {
				rowData["API MinVersion Compliance"] = strconv.FormatBool(portResult.APIServerTLSConfigCompliance.Version)
				rowData["API Cipher Compliance"] = strconv.FormatBool(portResult.APIServerTLSConfigCompliance.Ciphers)
			}
			if portResult.KubeletTLSConfigCompliance != nil {
				rowData["Kubelet MinVersion Compliance"] = strconv.FormatBool(portResult.KubeletTLSConfigCompliance.Version)
				rowData["Kubelet Cipher Compliance"] = strconv.FormatBool(portResult.KubeletTLSConfigCompliance.Ciphers)
			}
			if portResult.TLSReadiness != nil {
				rowData["TLS 1.3 Offered"] = boolToYesNo(portResult.TLSReadiness.TLS13Offered)
				rowData["TLS 1.2 Only"] = boolToYesNo(portResult.TLSReadiness.TLS12Only)
				rowData["PQC Capable"] = boolToYesNo(portResult.TLSReadiness.PQCCapable)
				rowData["Readiness Notes"] = stringOrNA(portResult.TLSReadiness.Notes)
			}

			row := buildCSVRow(csvColumns, rowData)
			if err := writer.Write(row); err != nil {
				return fmt.Errorf("failed to write CSV row: %w", err)
			}
			rowCount++
		}
	}

	return nil
}

func WriteScanErrorsCSV(results scanner.ScanResults, filename string) error {
	if len(results.ScanErrors) == 0 {
		slog.Info("No scan errors to write to CSV file")
		return nil
	}

	slog.Info("writing scan errors", "path", filename)

	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create scan errors CSV file: %w", err)
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	header := []string{"IP", "Port", "Error Type", "Error Message", "Pod Name", "Namespace", "Container"}
	if err := writer.Write(header); err != nil {
		return fmt.Errorf("failed to write scan errors CSV header: %w", err)
	}

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
			return fmt.Errorf("failed to write scan error row: %w", err)
		}
	}

	slog.Info("scan error rows written to CSV", "count", len(results.ScanErrors))
	return nil
}

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

func boolToYesNo(b bool) string {
	if b {
		return "Yes"
	}
	return "No"
}
