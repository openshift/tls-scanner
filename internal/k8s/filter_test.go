package k8s

import (
	"fmt"
	"testing"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func makePods(namespaces ...string) []PodInfo {
	var pods []PodInfo
	for _, ns := range namespaces {
		pods = append(pods, PodInfo{Name: "pod-" + ns, Namespace: ns, IPs: []string{"10.0.0.1"}})
	}
	return pods
}

func makePodsWithLabels(labels ...map[string]string) []PodInfo {
	var pods []PodInfo
	for i, lbls := range labels {
		pod := &v1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      fmt.Sprintf("pod-%d", i),
				Namespace: "default",
				Labels:    lbls,
			},
		}
		pods = append(pods, PodInfo{
			Name:      pod.Name,
			Namespace: pod.Namespace,
			IPs:       []string{"10.0.0.1"},
			Pod:       pod,
		})
	}
	return pods
}

func TestFilterPodsByNamespace(t *testing.T) {
	pods := makePods("openshift-apiserver", "openshift-etcd", "kube-system", "default")

	filtered := FilterPodsByNamespace(pods, "openshift-apiserver")
	if len(filtered) != 1 {
		t.Fatalf("expected 1 pod, got %d", len(filtered))
	}
	if filtered[0].Namespace != "openshift-apiserver" {
		t.Errorf("expected namespace openshift-apiserver, got %s", filtered[0].Namespace)
	}
}

func TestFilterPodsByNamespaceMultiple(t *testing.T) {
	pods := makePods("openshift-apiserver", "openshift-etcd", "kube-system", "default")

	filtered := FilterPodsByNamespace(pods, "openshift-apiserver,openshift-etcd")
	if len(filtered) != 2 {
		t.Fatalf("expected 2 pods, got %d", len(filtered))
	}

	ns := map[string]bool{}
	for _, p := range filtered {
		ns[p.Namespace] = true
	}
	if !ns["openshift-apiserver"] || !ns["openshift-etcd"] {
		t.Errorf("expected apiserver and etcd, got %v", ns)
	}
}

func TestFilterPodsByNamespaceEmpty(t *testing.T) {
	pods := makePods("openshift-apiserver", "openshift-etcd")

	filtered := FilterPodsByNamespace(pods, "")
	if len(filtered) != len(pods) {
		t.Errorf("empty filter should return all pods: expected %d, got %d", len(pods), len(filtered))
	}
}

func TestFilterPodsByNamespaceNoMatch(t *testing.T) {
	pods := makePods("openshift-apiserver", "openshift-etcd")

	filtered := FilterPodsByNamespace(pods, "nonexistent-ns")
	if len(filtered) != 0 {
		t.Errorf("expected 0 pods for nonexistent namespace, got %d", len(filtered))
	}
}

func TestFilterPodsByNamespaceWhitespace(t *testing.T) {
	pods := makePods("openshift-apiserver", "openshift-etcd", "kube-system")

	filtered := FilterPodsByNamespace(pods, " openshift-apiserver , openshift-etcd ")
	if len(filtered) != 2 {
		t.Fatalf("expected 2 pods (whitespace should be trimmed), got %d", len(filtered))
	}
}

func TestFilterPodsByExcludeLabelsEmpty(t *testing.T) {
	pods := makePodsWithLabels(
		map[string]string{"olm.catalogSource": "redhat-ods-operator"},
		map[string]string{"app": "my-operator"},
	)

	filtered := FilterPodsByExcludeLabels(pods, "")
	if len(filtered) != 2 {
		t.Errorf("empty exclude should return all pods: expected 2, got %d", len(filtered))
	}
}

func TestFilterPodsByExcludeLabelsKeyOnly(t *testing.T) {
	pods := makePodsWithLabels(
		map[string]string{"olm.catalogSource": "redhat-ods-operator"},
		map[string]string{"app": "my-operator"},
	)

	filtered := FilterPodsByExcludeLabels(pods, "olm.catalogSource")
	if len(filtered) != 1 {
		t.Fatalf("expected 1 pod after excluding by key, got %d", len(filtered))
	}
	if filtered[0].Pod.Labels["app"] != "my-operator" {
		t.Errorf("wrong pod kept: %v", filtered[0].Pod.Labels)
	}
}

func TestFilterPodsByExcludeLabelsKeyValue(t *testing.T) {
	pods := makePodsWithLabels(
		map[string]string{"olm.catalogSource": "redhat-ods-operator"},
		map[string]string{"olm.catalogSource": "community-operators"},
		map[string]string{"app": "my-operator"},
	)

	filtered := FilterPodsByExcludeLabels(pods, "olm.catalogSource=redhat-ods-operator")
	if len(filtered) != 2 {
		t.Fatalf("expected 2 pods, got %d", len(filtered))
	}
	for _, p := range filtered {
		if v := p.Pod.Labels["olm.catalogSource"]; v == "redhat-ods-operator" {
			t.Errorf("excluded pod leaked through: %v", p.Pod.Labels)
		}
	}
}

func TestFilterPodsByExcludeLabelsMultipleSelectors(t *testing.T) {
	pods := makePodsWithLabels(
		map[string]string{"olm.catalogSource": "rhods", "tier": "catalog"},
		map[string]string{"olm.catalogSource": "rhods"},
		map[string]string{"app": "my-operator"},
	)

	// Only exclude pods that have BOTH labels.
	filtered := FilterPodsByExcludeLabels(pods, "olm.catalogSource,tier=catalog")
	if len(filtered) != 2 {
		t.Fatalf("expected 2 pods (AND semantics), got %d", len(filtered))
	}
}

func TestFilterPodsByExcludeLabelsNilPod(t *testing.T) {
	pods := []PodInfo{
		{Name: "no-pod-ref", Namespace: "default", IPs: []string{"10.0.0.1"}},
	}

	// Should not panic; pod with nil Pod field has no labels so it is kept.
	filtered := FilterPodsByExcludeLabels(pods, "olm.catalogSource")
	if len(filtered) != 1 {
		t.Errorf("expected pod with nil Pod ref to be kept, got %d pods", len(filtered))
	}
}
