package main

import (
	"encoding/xml"
	"sync"

	configclientset "github.com/openshift/client-go/config/clientset/versioned"
	mcfgclientset "github.com/openshift/client-go/machineconfiguration/clientset/versioned"
	operatorclientset "github.com/openshift/client-go/operator/clientset/versioned"
	v1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

type NmapRun struct {
	XMLName xml.Name `xml:"nmaprun" json:"-"`
	Hosts   []Host   `xml:"host" json:"hosts"`
}

type Host struct {
	Status Status `xml:"status" json:"status"`
	Ports  []Port `xml:"ports>port" json:"ports"`
}

type Port struct {
	PortID   string   `xml:"portid,attr" json:"portid"`
	Protocol string   `xml:"protocol,attr" json:"protocol"`
	State    State    `xml:"state" json:"state"`
	Service  Service  `xml:"service" json:"service"`
	Scripts  []Script `xml:"script" json:"scripts"`
}

type Status struct {
	State  string `xml:"state,attr" json:"state"`
	Reason string `xml:"reason,attr" json:"reason"`
}

type State struct {
	State  string `xml:"state,attr" json:"state"`
	Reason string `xml:"reason,attr" json:"reason"`
}

type Service struct {
	Name string `xml:"name,attr" json:"name"`
}

type Script struct {
	ID     string  `xml:"id,attr" json:"id"`
	Tables []Table `xml:"table" json:"tables"`
	Elems  []Elem  `xml:"elem" json:"elems"`
}

type Table struct {
	XMLName xml.Name `xml:"table" json:"-"`
	Key     string   `xml:"key,attr" json:"key"`
	Tables  []Table  `xml:"table" json:"tables"`
	Elems   []Elem   `xml:"elem" json:"elems"`
}

type Elem struct {
	Key   string `xml:"key,attr" json:"key"`
	Value string `xml:",chardata" json:"value"`
}

type ScanResults struct {
	Timestamp         string              `json:"timestamp"`
	TotalIPs          int                 `json:"total_ips"`
	ScannedIPs        int                 `json:"scanned_ips"`
	IPResults         []IPResult          `json:"ip_results"`
	TLSSecurityConfig *TLSSecurityProfile `json:"tls_security_config,omitempty"`
	ScanErrors        []ScanError         `json:"scan_errors,omitempty"`
}

// ScanError represents a scanning error for a specific IP:port
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
	IP                 string              `json:"ip"`
	Status             string              `json:"status"`
	OpenPorts          []int               `json:"open_ports"`
	PortResults        []PortResult        `json:"port_results"`
	OpenshiftComponent *OpenshiftComponent `json:"openshift_component,omitempty"`
	Pod                *PodInfo            `json:"pod,omitempty"`
	Services           []ServiceInfo       `json:"services,omitempty"`
	Error              string              `json:"error,omitempty"`
}

type ServiceInfo struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
	Type      string `json:"type"`
	Ports     []int  `json:"ports,omitempty"`
}

type PodInfo struct {
	Name       string   // Pod name
	Namespace  string   // Pod namespace
	Image      string   // Container image
	IPs        []string // List of IPs assigned to the pod
	Containers []string // List of container names
}

type PortResult struct {
	Port                         int                        `json:"port"`
	Protocol                     string                     `json:"protocol"`
	State                        string                     `json:"state"`
	Service                      string                     `json:"service"`
	ProcessName                  string                     `json:"process_name,omitempty"`
	ContainerName                string                     `json:"container_name,omitempty"`
	NmapRun                      NmapRun                    `json:"nmap_details"` // deprecated
	TlsVersions                  []string                   `json:"tls_versions,omitempty"`
	TlsCiphers                   []string                   `json:"tls_ciphers,omitempty"`
	TlsCipherStrength            map[string]string          `json:"tls_cipher_strength,omitempty"`
	Error                        string                     `json:"error,omitempty"`
	IngressTLSConfigCompliance   *TLSConfigComplianceResult `json:"ingress_tls_config_compliance,omitempty"`
	APIServerTLSConfigCompliance *TLSConfigComplianceResult `json:"api_server_tls_config_compliance,omitempty"`
	KubeletTLSConfigCompliance   *TLSConfigComplianceResult `json:"kubelet_tls_config_compliance,omitempty"`
}

type TLSConfigComplianceResult struct {
	Version bool `json:"version"`
	Ciphers bool `json:"ciphers"`
}

type OpenshiftComponent struct {
	Component           string `json:"component"`
	SourceLocation      string `json:"source_location"`
	MaintainerComponent string `json:"maintainer_component"`
	IsBundle            bool   `json:"is_bundle"`
}

// TLSSecurityProfile represents TLS configuration from OpenShift components
type TLSSecurityProfile struct {
	IngressController *IngressTLSProfile   `json:"ingress_controller,omitempty"`
	APIServer         *APIServerTLSProfile `json:"api_server,omitempty"`
	KubeletConfig     *KubeletTLSProfile   `json:"kubelet_config,omitempty"`
}

type IngressTLSProfile struct {
	Type          string   `json:"type,omitempty"`
	MinTLSVersion string   `json:"min_tls_version,omitempty"`
	Ciphers       []string `json:"ciphers,omitempty"`
	Raw           string   `json:"raw,omitempty"`
}

type APIServerTLSProfile struct {
	Type          string   `json:"type,omitempty"`
	MinTLSVersion string   `json:"min_tls_version,omitempty"`
	Ciphers       []string `json:"ciphers,omitempty"`
	Raw           string   `json:"raw,omitempty"`
}

type KubeletTLSProfile struct {
	TLSCipherSuites []string `json:"tls_cipher_suites,omitempty"`
	MinTLSVersion   string   `json:"tls_min_version,omitempty"`
	Raw             string   `json:"raw,omitempty"`
}

type K8sClient struct {
	clientset                 *kubernetes.Clientset
	restCfg                   *rest.Config
	podIPMap                  map[string]v1.Pod
	processNameMap            map[string]map[int]string
	processDiscoveryAttempted map[string]bool
	processCacheMutex         sync.Mutex
	namespace                 string
	configClient              *configclientset.Clientset
	operatorClient            *operatorclientset.Clientset
	mcfgClient                *mcfgclientset.Clientset
}

var tlsVersionMap = map[string]string{
	"TLSv1.0": "VersionTLS10",
	"TLSv1.1": "VersionTLS11",
	"TLSv1.2": "VersionTLS12",
	"TLSv1.3": "VersionTLS13",
}

var tlsVersionValueMap = map[string]int{
	"TLSv1.0":      10,
	"TLSv1.1":      11,
	"TLSv1.2":      12,
	"TLSv1.3":      13,
	"VersionTLS10": 10,
	"VersionTLS11": 11,
	"VersionTLS12": 12,
	"VersionTLS13": 13,
}

// TODO fix this. The mapping from nmap to tls config is not very clear.
// nmapCipherToStandardCipherMap maps the cipher names from nmap's ssl-enum-ciphers script
// to the standard cipher suite names used in OpenShift TLS security profiles.
var ianaCipherToOpenSSLCipherMap = map[string]string{
	// Intermediate ciphers
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
	// Modern ciphers
	"TLS_AKE_WITH_AES_128_GCM_SHA256":       "TLS_AES_128_GCM_SHA256", // The standard cipher suites for "Modern" do not list a key exchange...
	"TLS_AKE_WITH_AES_256_GCM_SHA384":       "TLS_AES_256_GCM_SHA384",
	"TLS_AKE_WITH_CHACHA20_POLY1305_SHA256": "TLS_CHACHA20_POLY1305_SHA256",
	"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA":    "TLS_AES_128_CBC_SHA",
	"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA":    "TLS_AES_256_CBC_SHA",
}
