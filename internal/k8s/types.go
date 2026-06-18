package k8s

import (
	"sync"

	configv1 "github.com/openshift/api/config/v1"
	configclientset "github.com/openshift/client-go/config/clientset/versioned"
	mcfgclientset "github.com/openshift/client-go/machineconfiguration/clientset/versioned"
	operatorclientset "github.com/openshift/client-go/operator/clientset/versioned"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

type PodInfo struct {
	Name       string
	Namespace  string
	Image      string
	IPs        []string
	Containers []string
	Pod        *corev1.Pod `json:"-"`
}

type ListenInfo struct {
	Port          int
	ListenAddress string
	ProcessName   string
}

// ProcListenEntry holds a decoded listen address and socket inode from /proc/net/tcp.
type ProcListenEntry struct {
	Addr  string
	Inode uint64
}

type OpenshiftComponent struct {
	Component           string `json:"component"`
	SourceLocation      string `json:"source_location"`
	MaintainerComponent string `json:"maintainer_component"`
	IsBundle            bool   `json:"is_bundle"`
}

type TLSSecurityProfile struct {
	IngressController *IngressTLSProfile          `json:"ingress_controller,omitempty"`
	APIServer         *APIServerTLSProfile        `json:"api_server,omitempty"`
	KubeletConfig     *KubeletTLSProfile          `json:"kubelet_config,omitempty"`
	TLSAdherence      configv1.TLSAdherencePolicy `json:"tls_adherence,omitempty"`
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

type Client struct {
	clientset      *kubernetes.Clientset
	restCfg        *rest.Config
	dynamicClient  dynamic.Interface
	processNameMap map[string]map[int]string // TODO(refactor): redundant with listenInfoMap — remove
	listenInfoMap  map[string]map[int]ListenInfo
	// procListenAddrMap holds the decoded listen address for every port seen in
	// /proc/net/tcp(6). It covers all containers in a pod (shared network namespace).
	procListenAddrMap map[string]map[int]string
	// podOwnedPorts holds, per pod (keyed by "namespace/name"), the set of
	// ports whose listening socket inode was resolved to a process visible in
	// THAT pod's own PID namespace. Unlike processNameMap/listenInfoMap (which
	// are intentionally keyed by IP and shared across every pod that reports
	// it, since a given ip:port has exactly one real listener), ownership for
	// filtering purposes must never be merged across pods: hostNetwork pods on
	// the same node all share the node's IP, so an IP-keyed lookup would leak
	// ports legitimately owned by one hostNetwork pod (e.g. ovnkube-node) into
	// the scan target list of a completely unrelated one (see issue #85).
	podOwnedPorts     map[string]map[int]bool
	processCacheMutex sync.Mutex
	namespace         string
	configClient      *configclientset.Clientset
	operatorClient    *operatorclientset.Clientset
	mcfgClient        *mcfgclientset.Clientset
}
