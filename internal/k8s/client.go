package k8s

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"

	configclientset "github.com/openshift/client-go/config/clientset/versioned"
	mcfgclientset "github.com/openshift/client-go/machineconfiguration/clientset/versioned"
	operatorclientset "github.com/openshift/client-go/operator/clientset/versioned"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

func NewClient() (*Client, error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		slog.Warn("could not load in-cluster config, falling back to kubeconfig", "error", err)
		loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
		config, err = clientcmd.BuildConfigFromFlags("", loadingRules.GetDefaultFilename())
		if err != nil {
			return nil, fmt.Errorf("could not get kubernetes config: %v", err)
		}
		slog.Info("Successfully created Kubernetes client from kubeconfig file")
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

	dynamicClient, err := dynamic.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("could not create dynamic client: %v", err)
	}

	namespace := "default"
	if nsBytes, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace"); err == nil {
		namespace = string(nsBytes)
	}

	return &Client{
		clientset:                 clientset,
		restCfg:                   config,
		dynamicClient:             dynamicClient,
		processNameMap:            make(map[string]map[int]string),
		listenInfoMap:             make(map[string]map[int]ListenInfo),
		procListenAddrMap:         make(map[string]map[int]string),
		processDiscoveryAttempted: make(map[string]bool),
		namespace:                 namespace,
		configClient:              configClient,
		operatorClient:            operatorClient,
		mcfgClient:                mcfgClient,
	}, nil
}

func (c *Client) GetAllPodsInfo() ([]PodInfo, error) {
	slog.Info("Getting all pods from the cluster...")
	pods, err := c.clientset.CoreV1().Pods("").List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("could not list pods: %w", err)
	}

	var allPodsInfo []PodInfo
	for _, pod := range pods.Items {
		if pod.Status.PodIP == "" {
			slog.Debug("skipping pod with no IP address", "namespace", pod.Namespace, "pod", pod.Name, "phase", pod.Status.Phase)
			continue
		}

		containerNames := make([]string, 0, len(pod.Spec.Containers))
		for _, container := range pod.Spec.Containers {
			containerNames = append(containerNames, container.Name)
		}

		image := ""
		if len(pod.Spec.Containers) > 0 {
			image = pod.Spec.Containers[0].Image
		}

		podInfo := PodInfo{
			Name:       pod.Name,
			Namespace:  pod.Namespace,
			IPs:        []string{pod.Status.PodIP},
			Image:      image,
			Containers: containerNames,
			Pod:        &pod,
		}
		allPodsInfo = append(allPodsInfo, podInfo)
	}
	slog.Info("pods found in cluster", "count", len(allPodsInfo))

	totalIPs := 0
	uniqueIPs := make(map[string]bool)
	for _, pod := range allPodsInfo {
		for _, ip := range pod.IPs {
			totalIPs++
			uniqueIPs[ip] = true
		}
	}
	slog.Info("IP discovery summary", "totalIPs", totalIPs, "pods", len(allPodsInfo), "uniqueIPs", len(uniqueIPs))

	return allPodsInfo, nil
}

func (c *Client) FilterPodsByComponent(pods []PodInfo, componentFilter string) []PodInfo {
	if componentFilter == "" {
		return pods
	}

	slog.Info("filtering pods by component", "filter", componentFilter)
	filterComponents := strings.Split(componentFilter, ",")
	filterSet := make(map[string]struct{})
	for _, comp := range filterComponents {
		filterSet[strings.TrimSpace(comp)] = struct{}{}
	}

	var filtered []PodInfo
	for _, pod := range pods {
		// Extract component from pod labels (or fall back to image parsing)
		var componentName string
		if pod.Pod != nil && len(pod.Pod.Spec.Containers) > 0 {
			componentName = c.extractComponentFromPod(*pod.Pod, pod.Pod.Spec.Containers[0])
		} else {
			slog.Warn("pod has no pod or container info", "namespace", pod.Namespace, "name", pod.Name)
			continue
		}

		if _, ok := filterSet[componentName]; ok {
			filtered = append(filtered, pod)
		}
	}
	slog.Info("filtered pods by component", "remaining", len(filtered), "total", len(pods))
	return filtered
}

func FilterPodsByNamespace(pods []PodInfo, namespaceFilter string) []PodInfo {
	if namespaceFilter == "" {
		return pods
	}

	slog.Info("filtering pods by namespace", "filter", namespaceFilter)
	filterNamespaces := strings.Split(namespaceFilter, ",")
	filterSet := make(map[string]struct{})
	for _, ns := range filterNamespaces {
		filterSet[strings.TrimSpace(ns)] = struct{}{}
	}

	var filtered []PodInfo
	for _, pod := range pods {
		if _, ok := filterSet[pod.Namespace]; ok {
			filtered = append(filtered, pod)
		}
	}
	slog.Info("filtered pods by namespace", "remaining", len(filtered), "total", len(pods))
	return filtered
}
