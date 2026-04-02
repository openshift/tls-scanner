package scanner

import (
	"github.com/openshift/tls-scanner/internal/k8s"
)

type ScanRun struct {
	Hosts []Host `json:"hosts"`
}

type Host struct {
	Status Status `json:"status"`
	Ports  []Port `json:"ports"`
}

type Port struct {
	PortID   string   `json:"portid"`
	Protocol string   `json:"protocol"`
	State    State    `json:"state"`
	Service  Service  `json:"service"`
	Scripts  []Script `json:"scripts"`
}

type Status struct {
	State  string `json:"state"`
	Reason string `json:"reason"`
}

type State struct {
	State  string `json:"state"`
	Reason string `json:"reason"`
}

type Service struct {
	Name string `json:"name"`
}

type Script struct {
	ID     string  `json:"id"`
	Tables []Table `json:"tables"`
	Elems  []Elem  `json:"elems"`
}

type Table struct {
	Key    string  `json:"key"`
	Tables []Table `json:"tables"`
	Elems  []Elem  `json:"elems"`
}

type Elem struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type ScanResults struct {
	Timestamp         string                  `json:"timestamp"`
	TotalIPs          int                     `json:"total_ips"`
	ScannedIPs        int                     `json:"scanned_ips"`
	IPResults         []IPResult              `json:"ip_results"`
	TLSSecurityConfig *k8s.TLSSecurityProfile `json:"tls_security_config,omitempty"`
	ScanErrors        []ScanError             `json:"scan_errors,omitempty"`
}

type ScanError struct {
	IP        string `json:"ip"`
	Port      int    `json:"port"`
	ErrorType string `json:"error_type"`
	ErrorMsg  string `json:"error_message"`
	PodName   string `json:"pod_name,omitempty"`
	Namespace string `json:"namespace,omitempty"`
	Container string `json:"container,omitempty"`
}

type IPResult struct {
	IP                 string                  `json:"ip"`
	Status             string                  `json:"status"`
	OpenPorts          []int                   `json:"open_ports"`
	PortResults        []PortResult            `json:"port_results"`
	OpenshiftComponent *k8s.OpenshiftComponent `json:"openshift_component,omitempty"`
	Pod                *k8s.PodInfo            `json:"pod,omitempty"`
	Services           []ServiceInfo           `json:"services,omitempty"`
	Error              string                  `json:"error,omitempty"`
}

type ServiceInfo struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
	Type      string `json:"type"`
	Ports     []int  `json:"ports,omitempty"`
}

type ScanStatus string

const (
	StatusOK            ScanStatus = "OK"
	StatusNoTLS         ScanStatus = "NO_TLS"
	StatusLocalhostOnly ScanStatus = "LOCALHOST_ONLY"
	StatusNoPorts       ScanStatus = "NO_PORTS"
	// StatusProbePort indicates the port is used exclusively as a health probe
	// endpoint (liveness, readiness, or startup) with a plaintext protocol
	// (HTTP, TCP, or gRPC). TLS is not expected on such ports.
	StatusProbePort ScanStatus = "PROBE_PORT"
)

type PortResult struct {
	Port                         int                        `json:"port"`
	Protocol                     string                     `json:"protocol"`
	State                        string                     `json:"state"`
	Service                      string                     `json:"service"`
	ProcessName                  string                     `json:"process_name,omitempty"`
	ContainerName                string                     `json:"container_name,omitempty"`
	TlsVersions                  []string                   `json:"tls_versions,omitempty"`
	TlsCiphers                   []string                   `json:"tls_ciphers,omitempty"`
	TlsKeyExchange               *KeyExchangeInfo           `json:"tls_key_exchange,omitempty"`
	Error                        string                     `json:"error,omitempty"`
	Status                       ScanStatus                 `json:"status"`
	Reason                       string                     `json:"reason,omitempty"`
	ListenAddress                string                     `json:"listen_address,omitempty"`
	IngressTLSConfigCompliance   *TLSConfigComplianceResult `json:"ingress_tls_config_compliance,omitempty"`
	APIServerTLSConfigCompliance *TLSConfigComplianceResult `json:"api_server_tls_config_compliance,omitempty"`
	KubeletTLSConfigCompliance   *TLSConfigComplianceResult `json:"kubelet_tls_config_compliance,omitempty"`
	TLS13Supported               bool                       `json:"tls13_supported,omitempty"`
	MLKEMSupported               bool                       `json:"mlkem_supported,omitempty"`
	MLKEMCiphers                 []string                   `json:"mlkem_kems,omitempty"`
	AllKEMs                      []string                   `json:"all_kems,omitempty"`
	TLSReadiness                 *TLSReadiness              `json:"tls_readiness,omitempty"`
}

type TLSConfigComplianceResult struct {
	ConfiguredProfile string `json:"configured_profile,omitempty"`
	Version           bool   `json:"version"`
	Ciphers           bool   `json:"ciphers"`
}

type TLSReadiness struct {
	TLS13Offered bool     `json:"tls13_offered"`
	TLS12Only    bool     `json:"tls12_only"`
	PQCCapable   bool     `json:"pqc_capable"`
	MLKEMKEMs    []string `json:"mlkem_kems,omitempty"`
	AllKEMs      []string `json:"all_kems,omitempty"`
	Notes        string   `json:"notes,omitempty"`
}

type ForwardSecrecy struct {
	Supported bool     `json:"supported"`
	ECDHE     []string `json:"ecdhe,omitempty"`
	KEMs      []string `json:"kems,omitempty"`
}

type KeyExchangeInfo struct {
	Groups         []string        `json:"groups,omitempty"`
	ForwardSecrecy *ForwardSecrecy `json:"forward_secrecy,omitempty"`
}

type ScanJob struct {
	IP        string
	Port      int
	Pod       k8s.PodInfo
	Component *k8s.OpenshiftComponent
}

var TLSVersionValueMap = map[string]int{
	"TLSv1.0":      10,
	"TLSv1.1":      11,
	"TLSv1.2":      12,
	"TLSv1.3":      13,
	"VersionTLS10": 10,
	"VersionTLS11": 11,
	"VersionTLS12": 12,
	"VersionTLS13": 13,
}

var IanaCipherToOpenSSLCipherMap = map[string]string{
	"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256":       "TLS_AES_128_GCM_SHA256",
	"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384":       "TLS_AES_256_GCM_SHA384",
	"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256": "TLS_CHACHA20_POLY1305_SHA256",
	"ECDHE-ECDSA-AES128-GCM-SHA256":               "ECDHE-ECDSA-AES128-GCM-SHA256",
	"ECDHE-RSA-AES128-GCM-SHA256":                 "ECDHE-RSA-AES128-GCM-SHA256",
	"ECDHE-RSA-AES256-GCM-SHA384":                 "ECDHE-RSA-AES256-GCM-SHA384",
	"ECDHE-ECDSA-CHACHA20-POLY1305":               "ECDHE-ECDSA-CHACHA20-POLY1305",
	"ECDHE-RSA-CHACHA20-POLY1305":                 "ECDHE-RSA-CHACHA20-POLY1305",
	"DHE-RSA-AES128-GCM-SHA256":                   "DHE-RSA-AES128-GCM-SHA256",
	"DHE-RSA-AES256-GCM-SHA384":                   "DHE-RSA-AES256-GCM-SHA384",
	"TLS_AKE_WITH_AES_128_GCM_SHA256":             "TLS_AES_128_GCM_SHA256",
	"TLS_AKE_WITH_AES_256_GCM_SHA384":             "TLS_AES_256_GCM_SHA384",
	"TLS_AKE_WITH_CHACHA20_POLY1305_SHA256":       "TLS_CHACHA20_POLY1305_SHA256",
	"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA":          "TLS_AES_128_CBC_SHA",
	"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA":          "TLS_AES_256_CBC_SHA",
}
