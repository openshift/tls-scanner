package k8s

import (
	"testing"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func controllerRef(kind, name string) metav1.OwnerReference {
	isController := true
	return metav1.OwnerReference{Kind: kind, Name: name, Controller: &isController}
}

// Pod name shapes are taken from real CI scan results; every identity must be
// free of per-run randomness (hashes, random suffixes, node/cluster names).
func TestWorkloadIdentityForPod(t *testing.T) {
	t.Parallel()

	tests := []struct {
		testName string
		pod      *v1.Pod
		want     string
	}{
		{
			testName: "nil pod",
			pod:      nil,
			want:     "pod/unknown",
		},
		{
			testName: "deployment pod via replicaset with pod-template-hash",
			pod: &v1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:            "networking-console-plugin-54fdc79fd7-r2rk6",
					Labels:          map[string]string{"pod-template-hash": "54fdc79fd7"},
					OwnerReferences: []metav1.OwnerReference{controllerRef("ReplicaSet", "networking-console-plugin-54fdc79fd7")},
				},
			},
			want: "deployment/networking-console-plugin",
		},
		{
			testName: "replicaset pod without pod-template-hash",
			pod: &v1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:            "standalone-rs-abcde",
					OwnerReferences: []metav1.OwnerReference{controllerRef("ReplicaSet", "standalone-rs")},
				},
			},
			want: "replicaset/standalone-rs",
		},
		{
			testName: "daemonset pod",
			pod: &v1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:            "dns-default-6lmw2",
					OwnerReferences: []metav1.OwnerReference{controllerRef("DaemonSet", "dns-default")},
				},
			},
			want: "daemonset/dns-default",
		},
		{
			testName: "statefulset pod",
			pod: &v1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:            "prometheus-k8s-0",
					OwnerReferences: []metav1.OwnerReference{controllerRef("StatefulSet", "prometheus-k8s")},
				},
			},
			want: "statefulset/prometheus-k8s",
		},
		{
			testName: "static pod strips node name",
			pod: &v1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:            "etcd-ci-op-2677f6r3-83e8e-h9f6h-master-0",
					OwnerReferences: []metav1.OwnerReference{controllerRef("Node", "ci-op-2677f6r3-83e8e-h9f6h-master-0")},
				},
				Spec: v1.PodSpec{NodeName: "ci-op-2677f6r3-83e8e-h9f6h-master-0"},
			},
			want: "staticpod/etcd",
		},
		{
			testName: "job pod",
			pod: &v1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:            "collect-profiles-29135430-abcde",
					OwnerReferences: []metav1.OwnerReference{controllerRef("Job", "collect-profiles-29135430")},
				},
			},
			want: "job/collect-profiles-29135430",
		},
		{
			testName: "unowned guard pod strips node name",
			pod: &v1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name: "kube-apiserver-guard-ci-op-2677f6r3-83e8e-h9f6h-master-1",
				},
				Spec: v1.PodSpec{NodeName: "ci-op-2677f6r3-83e8e-h9f6h-master-1"},
			},
			want: "pod/kube-apiserver-guard",
		},
		{
			testName: "unowned pod whose name does not embed the node name",
			pod: &v1.Pod{
				ObjectMeta: metav1.ObjectMeta{Name: "some-standalone-pod"},
				Spec:       v1.PodSpec{NodeName: "worker-1"},
			},
			want: "pod/some-standalone-pod",
		},
		{
			testName: "unknown controller kind",
			pod: &v1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:            "redhat-operators-td4zz",
					OwnerReferences: []metav1.OwnerReference{controllerRef("CatalogSource", "redhat-operators")},
				},
			},
			want: "catalogsource/redhat-operators",
		},
	}

	for _, tc := range tests {
		t.Run(tc.testName, func(t *testing.T) {
			t.Parallel()
			if got := WorkloadIdentityForPod(tc.pod).String(); got != tc.want {
				t.Errorf("WorkloadIdentityForPod() = %q, want %q", got, tc.want)
			}
		})
	}
}
