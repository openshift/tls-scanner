package scanner

import (
	"encoding/json"
	"log"
	"os/exec"
	"strings"
)

func IsTestSSLInstalled() bool {
	_, err := exec.LookPath("testssl.sh")
	return err == nil
}

func ParseTestSSLOutput(jsonData []byte, host, port string) ScanRun {
	var rawData []map[string]interface{}

	if err := json.Unmarshal(jsonData, &rawData); err != nil {
		log.Printf("Error parsing testssl.sh JSON output: %v", err)
		return ScanRun{Hosts: []Host{{
			Ports: []Port{{
				PortID:   port,
				Protocol: "tcp",
				State:    State{State: "open"},
				Service:  Service{Name: "ssl/tls"},
			}},
		}}}
	}

	return convertTestSSLToScanRun(rawData, host, port)
}

func convertTestSSLToScanRun(rawData []map[string]interface{}, host, port string) ScanRun {
	scanResult := ScanRun{
		Hosts: []Host{{
			Status: Status{State: "up"},
			Ports: []Port{{
				PortID:   port,
				Protocol: "tcp",
				State:    State{State: "open"},
				Service:  Service{Name: "ssl/tls"},
				Scripts:  []Script{},
			}},
		}},
	}

	tlsScript := Script{
		ID:     "ssl-enum-ciphers",
		Tables: []Table{},
	}

	tlsVersions := make(map[string][]Table)
	detectedVersions := make(map[string]bool)

	for _, finding := range rawData {
		id, _ := finding["id"].(string)
		findingValue, _ := finding["finding"].(string)
		severity, _ := finding["severity"].(string)

		if findingValue == "" || findingValue == "not offered" {
			continue
		}

		if isProtocolID(id) {
			versionName := extractTLSVersion(id)
			if versionName != "" && strings.HasPrefix(findingValue, "offered") {
				detectedVersions[versionName] = true
				if _, exists := tlsVersions[versionName]; !exists {
					tlsVersions[versionName] = []Table{}
				}
			}
		}

		isCipherEntry := (strings.HasPrefix(id, "cipher-") || strings.HasPrefix(id, "cipher_")) &&
			!strings.Contains(id, "order") &&
			!strings.Contains(id, "list") &&
			!strings.Contains(id, "score")
		if isCipherEntry {
			cipherName := extractCipherName(findingValue)
			if cipherName == "" {
				cipherName = strings.TrimPrefix(id, "cipher-")
				cipherName = strings.TrimPrefix(cipherName, "cipher_")
			}

			versionName := extractTLSVersionFromCipherID(id, finding)

			if versionName != "" {
				detectedVersions[versionName] = true
				if _, exists := tlsVersions[versionName]; !exists {
					tlsVersions[versionName] = []Table{}
				}

				cipherTable := Table{
					Key: "",
					Elems: []Elem{
						{Key: "name", Value: cipherName},
						{Key: "strength", Value: mapSeverityToStrength(severity)},
					},
				}
				tlsVersions[versionName] = append(tlsVersions[versionName], cipherTable)
			}
		}
	}

	for version := range detectedVersions {
		ciphers := tlsVersions[version]

		versionTable := Table{
			Key:    version,
			Tables: []Table{},
			Elems:  []Elem{},
		}

		if len(ciphers) > 0 {
			ciphersTable := Table{
				Key:    "ciphers",
				Tables: ciphers,
				Elems:  []Elem{},
			}
			versionTable.Tables = append(versionTable.Tables, ciphersTable)
		}

		tlsScript.Tables = append(tlsScript.Tables, versionTable)
	}

	scanResult.Hosts[0].Ports[0].Scripts = append(scanResult.Hosts[0].Ports[0].Scripts, tlsScript)

	return scanResult
}

func extractCipherName(finding string) string {
	parts := strings.Fields(finding)
	if len(parts) >= 2 {
		return parts[len(parts)-1]
	}
	if len(parts) == 1 {
		return parts[0]
	}
	return ""
}

func isProtocolID(id string) bool {
	lower := strings.ToLower(id)
	return strings.HasPrefix(lower, "tls") || strings.HasPrefix(lower, "ssl")
}

func extractTLSVersion(id string) string {
	lower := strings.ToLower(id)
	switch {
	case strings.Contains(lower, "tls1_3"):
		return "TLSv1.3"
	case strings.Contains(lower, "tls1_2"):
		return "TLSv1.2"
	case strings.Contains(lower, "tls1_1"):
		return "TLSv1.1"
	case strings.Contains(lower, "tls1"):
		return "TLSv1.0"
	case strings.Contains(lower, "ssl3") || strings.Contains(lower, "sslv3"):
		return "SSLv3"
	case strings.Contains(lower, "ssl2") || strings.Contains(lower, "sslv2"):
		return "SSLv2"
	default:
		return ""
	}
}

func extractTLSVersionFromCipherID(id string, finding map[string]interface{}) string {
	if strings.Contains(id, "tls1_3") {
		return "TLSv1.3"
	}
	if strings.Contains(id, "tls1_2") {
		return "TLSv1.2"
	}
	if strings.Contains(id, "tls1_1") {
		return "TLSv1.1"
	}
	if strings.Contains(id, "tls1_0") || strings.Contains(id, "tls1-") {
		return "TLSv1.0"
	}
	if strings.Contains(id, "ssl3") {
		return "SSLv3"
	}
	if strings.Contains(id, "ssl2") {
		return "SSLv2"
	}

	if section, ok := finding["section"].(string); ok {
		ver := extractTLSVersion(section)
		if ver != "" {
			return ver
		}
	}

	findingValue, _ := finding["finding"].(string)
	if strings.Contains(findingValue, "TLS_AES_") || strings.Contains(findingValue, "TLS_CHACHA20_") {
		return "TLSv1.3"
	}

	return "TLSv1.2"
}

func mapSeverityToStrength(severity string) string {
	switch severity {
	case "OK", "LOW":
		return "A"
	case "MEDIUM":
		return "B"
	case "HIGH":
		return "C"
	case "CRITICAL":
		return "F"
	default:
		return "unknown"
	}
}

func ExtractKeyExchangeFromTestSSL(jsonData []byte) *KeyExchangeInfo {
	var rawData []map[string]interface{}
	if err := json.Unmarshal(jsonData, &rawData); err != nil {
		log.Printf("Error parsing testssl.sh JSON for key exchange: %v", err)
		return nil
	}

	keyExchange := &KeyExchangeInfo{
		Groups:         []string{},
		ForwardSecrecy: &ForwardSecrecy{},
	}

	var ecdheCiphers []string
	var kemGroups []string
	var allGroups []string

	for _, finding := range rawData {
		id, _ := finding["id"].(string)
		findingValue, _ := finding["finding"].(string)

		if findingValue == "" || findingValue == "not offered" || findingValue == "not supported" {
			continue
		}

		switch {
		case id == "FS":
			keyExchange.ForwardSecrecy.Supported = strings.Contains(strings.ToLower(findingValue), "offered") ||
				strings.Contains(strings.ToLower(findingValue), "yes") ||
				strings.Contains(strings.ToLower(findingValue), "ok")

		case id == "FS_ECDHE" || id == "FS_ciphers":
			parts := strings.Fields(findingValue)
			for _, p := range parts {
				p = strings.TrimSpace(p)
				if p != "" && !stringInSlice(p, ecdheCiphers) {
					ecdheCiphers = append(ecdheCiphers, p)
				}
			}

		case id == "FS_KEMs" || strings.HasPrefix(id, "FS_KEM"):
			parts := strings.Fields(findingValue)
			for _, p := range parts {
				p = strings.TrimSpace(p)
				if p != "" && !stringInSlice(p, kemGroups) {
					kemGroups = append(kemGroups, p)
				}
			}

		case id == "supported_groups" || id == "named_groups" || id == "curves":
			parts := strings.Fields(findingValue)
			for _, p := range parts {
				p = strings.TrimSpace(p)
				if p != "" && !stringInSlice(p, allGroups) {
					allGroups = append(allGroups, p)
					if IsKEMGroup(p) && !stringInSlice(p, kemGroups) {
						kemGroups = append(kemGroups, p)
					}
				}
			}

		case strings.HasPrefix(id, "group_") || strings.HasPrefix(id, "curve_"):
			groupName := strings.TrimPrefix(id, "group_")
			groupName = strings.TrimPrefix(groupName, "curve_")
			if findingValue == "offered" || findingValue == "yes" || strings.Contains(strings.ToLower(findingValue), "supported") {
				if !stringInSlice(groupName, allGroups) {
					allGroups = append(allGroups, groupName)
				}
				if IsKEMGroup(groupName) && !stringInSlice(groupName, kemGroups) {
					kemGroups = append(kemGroups, groupName)
				}
			}
		}
	}

	keyExchange.Groups = allGroups
	keyExchange.ForwardSecrecy.ECDHE = ecdheCiphers
	keyExchange.ForwardSecrecy.KEMs = kemGroups

	if len(kemGroups) > 0 {
		keyExchange.ForwardSecrecy.Supported = true
	}

	if len(allGroups) == 0 && len(ecdheCiphers) == 0 && len(kemGroups) == 0 && !keyExchange.ForwardSecrecy.Supported {
		return nil
	}

	return keyExchange
}

func IsKEMGroup(name string) bool {
	lower := strings.ToLower(name)
	return strings.Contains(lower, "mlkem") ||
		strings.Contains(lower, "ml-kem") ||
		strings.Contains(lower, "kyber") ||
		strings.Contains(lower, "sntrup") ||
		strings.Contains(lower, "bike") ||
		strings.Contains(lower, "hqc")
}

func GroupTestSSLOutputByIPPort(jsonData []byte) (map[string][]map[string]interface{}, error) {
	var rawData []map[string]interface{}
	if err := json.Unmarshal(jsonData, &rawData); err != nil {
		return nil, err
	}

	grouped := make(map[string][]map[string]interface{})
	for _, finding := range rawData {
		ip, _ := finding["ip"].(string)
		port, _ := finding["port"].(string)
		if idx := strings.Index(ip, "/"); idx != -1 {
			ip = ip[:idx]
		}
		if ip == "" || port == "" {
			continue
		}
		key := targetKey(ip, port)
		grouped[key] = append(grouped[key], finding)
	}

	return grouped, nil
}

func ExtractTLSInfo(scanRun ScanRun) []string {
	var tlsVersions []string

	for _, host := range scanRun.Hosts {
		for _, tlsPort := range host.Ports {
			for _, script := range tlsPort.Scripts {
				if script.ID == "ssl-enum-ciphers" {
					for _, table := range script.Tables {
						tlsVersion := table.Key
						if tlsVersion != "" {
							tlsVersions = append(tlsVersions, tlsVersion)
						}
					}
				}
			}
		}
	}

	return removeDuplicates(tlsVersions)
}
