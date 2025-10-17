package main

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"

	configv1 "github.com/openshift/api/config/v1"
	configclientset "github.com/openshift/client-go/config/clientset/versioned"
	mcfgclientset "github.com/openshift/client-go/machineconfiguration/clientset/versioned"
	operatorclientset "github.com/openshift/client-go/operator/clientset/versioned"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/remotecommand"
)

func newK8sClient() (*K8sClient, error) {
	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
	config, err := clientcmd.BuildConfigFromFlags("", loadingRules.GetDefaultFilename())
	if err != nil {
		return nil, fmt.Errorf("could not get kubernetes config: %v", err)
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}

	configClient, err := configclientset.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("could not create openshift config client: %v", err)
	}

	operatorClient, err := operatorclientset.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("could not create openshift operator client: %v", err)
	}

	mcfgClient, err := mcfgclientset.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("could not create openshift machineconfig client: %v", err)
	}

	namespace := "default" // Or get from config
	if nsBytes, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace"); err == nil {
		namespace = string(nsBytes)
	}

	return &K8sClient{
		clientset:                 clientset,
		restCfg:                   config,
		podIPMap:                  make(map[string]v1.Pod),
		processNameMap:            make(map[string]map[int]string),
		processDiscoveryAttempted: make(map[string]bool),
		namespace:                 namespace,
		configClient:              configClient,
		operatorClient:            operatorClient,
		mcfgClient:                mcfgClient,
	}, nil
}

func (k *K8sClient) getOpenshiftComponentFromImage(image string) (*OpenshiftComponent, error) {
	log.Printf("Analyzing OpenShift image: %s", image)

	// Parse the image reference to extract component information
	component := k.parseOpenshiftComponentFromImageRef(image)
	if component != nil {
		log.Printf("Successfully parsed component info from image: %s -> %s", image, component.Component)
		return component, nil
	}

	// Fallback: try to get additional metadata from running pods using this image
	log.Printf("Attempting to gather component info from cluster metadata for: %s", image)
	return k.getComponentFromClusterMetadata(image)
}

// TODO: This is much different than how check-payload does it...
// https://github.com/openshift/check-payload/blob/1c3541964ab045305b9754305e99ab80d35da8e4/internal/podman/podman.go#L157
func (k *K8sClient) parseOpenshiftComponentFromImageRef(image string) *OpenshiftComponent {
	// Handle OpenShift release images - similar to check-payload approach
	if strings.Contains(image, "quay.io/openshift-release-dev") {
		// Extract component from OpenShift release image path
		// Format: quay.io/openshift-release-dev/ocp-v4.0-art-dev@sha256:...
		component := &OpenshiftComponent{
			SourceLocation:      "quay.io/openshift-release-dev",
			MaintainerComponent: "openshift",
			IsBundle:            false,
		}

		// Parse component name from image path or labels we might find
		if strings.Contains(image, "oauth-openshift") {
			component.Component = "oauth-openshift"
		} else if strings.Contains(image, "apiserver") {
			component.Component = "openshift-apiserver"
		} else if strings.Contains(image, "controller-manager") {
			component.Component = "openshift-controller-manager"
		} else {
			// Default component name from sha or extract from known patterns
			component.Component = "openshift-component"
		}

		return component
	}

	// Handle internal OpenShift registry images
	if strings.Contains(image, "image-registry.openshift-image-registry.svc") {
		parts := strings.Split(image, "/")
		if len(parts) >= 3 {
			return &OpenshiftComponent{
				Component:           parts[len(parts)-1], // Use image name as component
				SourceLocation:      "internal-registry",
				MaintainerComponent: "user",
				IsBundle:            false,
			}
		}
	}

	// Handle other registries (quay.io, registry.redhat.com, etc.)
	if strings.Contains(image, "quay.io") || strings.Contains(image, "registry.redhat.com") {
		return &OpenshiftComponent{
			Component:           k.extractComponentNameFromImage(image),
			SourceLocation:      k.extractRegistryFromImage(image),
			MaintainerComponent: "redhat",
			IsBundle:            false,
		}
	}

	return nil
}

func (k *K8sClient) getComponentFromClusterMetadata(image string) (*OpenshiftComponent, error) {
	// Try to find pods using this image and extract metadata
	log.Printf("Searching cluster for pods using image: %s", image)

	pods, err := k.clientset.CoreV1().Pods("").List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list pods for image metadata: %v", err)
	}

	// Look for pods using this exact image
	for _, pod := range pods.Items {
		for _, container := range pod.Spec.Containers {
			if container.Image == image {
				// Extract component info from pod labels or annotations
				component := &OpenshiftComponent{
					Component:           k.extractComponentFromPod(pod, container),
					SourceLocation:      k.extractRegistryFromImage(image),
					MaintainerComponent: k.extractMaintainerFromPod(pod),
					IsBundle:            false,
				}
				return component, nil
			}
		}
	}

	// If no exact match found, return basic info
	return &OpenshiftComponent{
		Component:           k.extractComponentNameFromImage(image),
		SourceLocation:      "unknown",
		MaintainerComponent: "unknown",
		IsBundle:            false,
	}, nil
}

func (k *K8sClient) extractComponentNameFromImage(image string) string {
	// Extract component name from image URL
	parts := strings.Split(image, "/")
	if len(parts) > 0 {
		// Get the last part (image name)
		imageName := parts[len(parts)-1]
		// Remove tag/sha if present
		if strings.Contains(imageName, ":") {
			imageName = strings.Split(imageName, ":")[0]
		}
		if strings.Contains(imageName, "@") {
			imageName = strings.Split(imageName, "@")[0]
		}
		return imageName
	}
	return "unknown"
}

func (k *K8sClient) extractRegistryFromImage(image string) string {
	if strings.Contains(image, "quay.io") {
		return "quay.io"
	} else if strings.Contains(image, "registry.redhat.com") {
		return "registry.redhat.com"
	} else if strings.Contains(image, "image-registry.openshift-image-registry.svc") {
		return "internal-registry"
	}
	return strings.Split(image, "/")[0]
}

func (k *K8sClient) extractComponentFromPod(pod v1.Pod, container v1.Container) string {
	if component, exists := pod.Labels["app"]; exists {
		return component
	}
	if component, exists := pod.Labels["component"]; exists {
		return component
	}
	if component, exists := pod.Labels["app.kubernetes.io/name"]; exists {
		return component
	}
	// Fallback to container name or image name
	if container.Name != "" {
		return container.Name
	}
	return k.extractComponentNameFromImage(container.Image)
}

func (k *K8sClient) extractMaintainerFromPod(pod v1.Pod) string {
	if strings.HasPrefix(pod.Namespace, "openshift-") {
		return "openshift"
	}
	if strings.HasPrefix(pod.Namespace, "kube-") {
		return "kubernetes"
	}
	if maintainer, exists := pod.Labels["maintainer"]; exists {
		return maintainer
	}
	return "unknown"
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// getProcessMapForPod executes a single lsof command to get all listening ports and processes for a pod
func (k *K8sClient) getProcessMapForPod(pod PodInfo) (map[string]map[int]string, error) {
	processMap := make(map[string]map[int]string)
	if len(pod.Containers) == 0 {
		return processMap, nil
	}

	// lsof command to get port and command name for all listening TCP ports
	command := []string{"/bin/sh", "-c", "lsof -i -sTCP:LISTEN -P -n -F cn"}

	// We only need to run this in one container, as networking is shared across the pod
	containerName := pod.Containers[0]
	log.Printf("Executing lsof command in pod %s/%s, container %s: %v", pod.Namespace, pod.Name, containerName, command)

	req := k.clientset.CoreV1().RESTClient().Post().
		Resource("pods").
		Name(pod.Name).
		Namespace(pod.Namespace).
		SubResource("exec")

	req.VersionedParams(&v1.PodExecOptions{
		Container: containerName,
		Command:   command,
		Stdin:     false,
		Stdout:    true,
		Stderr:    true,
		TTY:       false,
	}, scheme.ParameterCodec)

	exec, err := remotecommand.NewSPDYExecutor(k.restCfg, "POST", req.URL())
	if err != nil {
		return nil, fmt.Errorf("failed to create executor for pod %s: %v", pod.Name, err)
	}

	var stdout, stderr bytes.Buffer
	err = exec.StreamWithContext(context.Background(), remotecommand.StreamOptions{
		Stdout: &stdout,
		Stderr: &stderr,
	})

	// Always log stdout and stderr for debugging purposes
	log.Printf("lsof command for pod %s/%s finished.", pod.Namespace, pod.Name)
	log.Printf("lsof stdout:\n%s", stdout.String())
	log.Printf("lsof stderr:\n%s", stderr.String())

	if err != nil {
		return nil, fmt.Errorf("exec failed on pod %s: %v, stdout: %s, stderr: %s", pod.Name, err, stdout.String(), stderr.String())
	}

	if stdout.Len() == 0 {
		log.Printf("lsof command returned empty stdout for pod %s/%s. This could be normal (no listening processes) or an issue.", pod.Namespace, pod.Name)
	}

	// Parse the lsof output
	scanner := bufio.NewScanner(&stdout)
	var currentProcess string
	for scanner.Scan() {
		line := scanner.Text()
		log.Printf("Parsing lsof output line for pod %s/%s: %q", pod.Namespace, pod.Name, line)
		if len(line) > 1 {
			fieldType := line[0]
			fieldValue := line[1:]

			switch fieldType {
			case 'c':
				currentProcess = fieldValue
			case 'n':
				// Format is expected to be something like *:port or IP:port
				parts := strings.Split(fieldValue, ":")
				if len(parts) == 2 {
					portStr := parts[1]
					port, err := strconv.Atoi(portStr)
					if err == nil {
						// Map all pod IPs to this port and process
						for _, ip := range pod.IPs {
							if _, ok := processMap[ip]; !ok {
								processMap[ip] = make(map[int]string)
							}
							processMap[ip][port] = currentProcess
							log.Printf("Mapped pod %s/%s IP %s port %d to process %s", pod.Namespace, pod.Name, ip, port, currentProcess)
						}
					} else {
						log.Printf("Error converting port to integer for pod %s/%s: '%s' from line '%s'", pod.Namespace, pod.Name, portStr, line)
					}
				} else {
					log.Printf("Unexpected format for network address from lsof for pod %s/%s: '%s'", pod.Namespace, pod.Name, fieldValue)
				}
			}
		}
	}

	return processMap, nil
}

func (k *K8sClient) getAndCachePodProcesses(pod PodInfo) {
	k.processCacheMutex.Lock()
	if k.processDiscoveryAttempted[pod.Name] {
		k.processCacheMutex.Unlock()
		return // Discovery already attempted for this pod
	}
	// Mark as attempted before unlocking to prevent other goroutines from trying
	k.processDiscoveryAttempted[pod.Name] = true
	k.processCacheMutex.Unlock()

	processMap, err := k.getProcessMapForPod(pod)
	if err != nil {
		log.Printf("Could not get process map for pod %s/%s: %v", pod.Namespace, pod.Name, err)
		return
	}

	if len(processMap) > 0 {
		k.processCacheMutex.Lock()
		defer k.processCacheMutex.Unlock()
		for ip, portMap := range processMap {
			if _, ok := k.processNameMap[ip]; !ok {
				k.processNameMap[ip] = make(map[int]string)
			}
			for port, process := range portMap {
				k.processNameMap[ip][port] = process
			}
		}
	}
}

// getTLSSecurityProfile collects TLS security profile configurations from OpenShift components
func (k *K8sClient) getTLSSecurityProfile() (*TLSSecurityProfile, error) {
	log.Printf("Collecting TLS security profiles from OpenShift components...")

	profile := &TLSSecurityProfile{}

	// Collect Ingress Controller TLS configuration
	if ingressTLS, err := k.getIngressControllerTLS(); err != nil {
		log.Printf("Warning: Could not get Ingress Controller TLS config: %v", err)
	} else {
		profile.IngressController = ingressTLS
	}

	// Collect API Server TLS configuration
	if apiServerTLS, err := k.getAPIServerTLS(); err != nil {
		log.Printf("Warning: Could not get API Server TLS config: %v", err)
	} else {
		profile.APIServer = apiServerTLS
	}

	// Collect Kubelet TLS configuration
	if kubeletTLS, err := k.getKubeletTLS(); err != nil {
		log.Printf("Warning: Could not get Kubelet TLS config: %v", err)
	} else {
		profile.KubeletConfig = kubeletTLS
	}

	return profile, nil
}

// getIngressControllerTLS gets TLS configuration from Ingress Controller
func (k *K8sClient) getIngressControllerTLS() (*IngressTLSProfile, error) {
	// TODO this namespace may be wrong for ingress
	ingress, err := k.operatorClient.OperatorV1().IngressControllers("openshift-ingress-operator").Get(context.Background(), "default", metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get IngressController custom resource: %v", err)
	}

	profile := &IngressTLSProfile{}

	// "If unset, the default is based on the apiservers.config.openshift.io/cluster resource."
	// TODO make this just use the API Server TLS profile if not set here?
	if ingress.Spec.TLSSecurityProfile == nil {
		profile.Type = "API Config Server"
		return profile, nil
	}

	profile.Type = string(ingress.Spec.TLSSecurityProfile.Type)
	if custom := ingress.Spec.TLSSecurityProfile.Custom; custom != nil {
		profile.Ciphers = custom.TLSProfileSpec.Ciphers
		profile.MinTLSVersion = string(custom.TLSProfileSpec.MinTLSVersion)
		return profile, nil
	}
	if ingress.Spec.TLSSecurityProfile.Type == configv1.TLSProfileOldType {
		profile.Ciphers = configv1.TLSProfiles[configv1.TLSProfileOldType].Ciphers
		profile.MinTLSVersion = string(configv1.TLSProfiles[configv1.TLSProfileOldType].MinTLSVersion)
	}
	if ingress.Spec.TLSSecurityProfile.Type == configv1.TLSProfileIntermediateType {
		profile.Ciphers = configv1.TLSProfiles[configv1.TLSProfileIntermediateType].Ciphers
		profile.MinTLSVersion = string(configv1.TLSProfiles[configv1.TLSProfileIntermediateType].MinTLSVersion)
	}
	if ingress.Spec.TLSSecurityProfile.Type == configv1.TLSProfileModernType {
		profile.Ciphers = configv1.TLSProfiles[configv1.TLSProfileModernType].Ciphers
		profile.MinTLSVersion = string(configv1.TLSProfiles[configv1.TLSProfileModernType].MinTLSVersion)
	}

	return profile, nil
}

// getAPIServerTLS gets TLS configuration from API Server
func (k *K8sClient) getAPIServerTLS() (*APIServerTLSProfile, error) {
	apiserver, err := k.configClient.ConfigV1().APIServers().Get(context.Background(), "cluster", metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get APIServer custom resource: %v", err)
	}

	profile := &APIServerTLSProfile{}

	// If unset, a default (which may change between releases) is chosen. Note that only Old,
	// Intermediate and Custom profiles are currently supported, and the maximum available
	// minTLSVersion is VersionTLS12.
	if apiserver.Spec.TLSSecurityProfile == nil {
		profile.Type = "Default"
		return profile, nil
	}

	profile.Type = string(apiserver.Spec.TLSSecurityProfile.Type)
	if custom := apiserver.Spec.TLSSecurityProfile.Custom; custom != nil {
		profile.Ciphers = custom.TLSProfileSpec.Ciphers
		profile.MinTLSVersion = string(custom.TLSProfileSpec.MinTLSVersion)
	}
	if apiserver.Spec.TLSSecurityProfile.Type == configv1.TLSProfileOldType {
		profile.Ciphers = configv1.TLSProfiles[configv1.TLSProfileOldType].Ciphers
		profile.MinTLSVersion = string(configv1.TLSProfiles[configv1.TLSProfileOldType].MinTLSVersion)
	}
	if apiserver.Spec.TLSSecurityProfile.Type == configv1.TLSProfileIntermediateType {
		profile.Ciphers = configv1.TLSProfiles[configv1.TLSProfileIntermediateType].Ciphers
		profile.MinTLSVersion = string(configv1.TLSProfiles[configv1.TLSProfileIntermediateType].MinTLSVersion)
	}
	if apiserver.Spec.TLSSecurityProfile.Type == configv1.TLSProfileModernType {
		profile.Ciphers = configv1.TLSProfiles[configv1.TLSProfileModernType].Ciphers
		profile.MinTLSVersion = string(configv1.TLSProfiles[configv1.TLSProfileModernType].MinTLSVersion)
	}

	return profile, nil
}

// getKubeletTLS gets the cluster-wide configured Kubelet TLS profile.
func (k *K8sClient) getKubeletTLS() (*KubeletTLSProfile, error) {
	kubeletConfigs, err := k.mcfgClient.MachineconfigurationV1().KubeletConfigs().List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list KubeletConfigs: %v", err)
	}

	// In a standard cluster, we are looking for the KubeletConfig that contains the TLS profile.
	// There might be multiple, but typically one will have the desired spec.
	for _, kc := range kubeletConfigs.Items {
		if kc.Spec.TLSSecurityProfile != nil {
			profile := &KubeletTLSProfile{}
			tlsProfile := kc.Spec.TLSSecurityProfile

			if tlsProfile.Type == configv1.TLSProfileCustomType {
				if custom := tlsProfile.Custom; custom != nil {
					profile.TLSCipherSuites = custom.TLSProfileSpec.Ciphers
					profile.MinTLSVersion = string(custom.TLSProfileSpec.MinTLSVersion)
				}
			} else if tlsProfile.Type != "" {
				// For built-in profiles, get the spec from the configv1 constants
				if predefined, ok := configv1.TLSProfiles[tlsProfile.Type]; ok {
					profile.TLSCipherSuites = predefined.Ciphers
					profile.MinTLSVersion = string(predefined.MinTLSVersion)
				}
			}
			return profile, nil
		}
	}

	return nil, fmt.Errorf("no KubeletConfig with a TLSSecurityProfile found in the cluster")
}

func (k *K8sClient) getAllPodsInfo() []PodInfo {
	pods, err := k.clientset.CoreV1().Pods("").List(context.Background(), metav1.ListOptions{}) // TODO handle error
	if err != nil {
		log.Printf("Error getting pods for info: %v", err)
		return nil
	}

	// Build pod IP to Pod mapping
	for _, pod := range pods.Items {
		if pod.Status.PodIP != "" {
			k.podIPMap[pod.Status.PodIP] = pod
		}
	}

	infos := make([]PodInfo, 0, len(pods.Items))
	for i := range pods.Items {
		pod := pods.Items[i]
		if pod.Status.PodIP == "" || pod.Status.Phase != v1.PodRunning {
			continue
		}

		var containerNames []string
		var image string
		if len(pod.Spec.Containers) > 0 {
			image = pod.Spec.Containers[0].Image // TODO Not sure if this matters taking the first one for now
			for _, c := range pod.Spec.Containers {
				containerNames = append(containerNames, c.Name)
			}
		}

		var ips []string
		for _, podIP := range pod.Status.PodIPs {
			ips = append(ips, podIP.IP)
		}

		if len(ips) > 0 {
			infos = append(infos, PodInfo{
				Name:       pod.Name,
				Namespace:  pod.Namespace,
				Image:      image,
				IPs:        ips,
				Containers: containerNames,
				Pod:        &pod,
			})
		}
	}
	return infos
}
