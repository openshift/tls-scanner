package k8s

import (
	"strings"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// WorkloadIdentity is a run-stable identity for the workload that owns a pod.
// Pod names embed per-run randomness (ReplicaSet pod-template hashes, random
// suffixes, node names containing the cluster ID), so results keyed by pod
// name cannot be aggregated across CI runs. The owning workload's identity is
// the same on every run of the same payload.
type WorkloadIdentity struct {
	Kind string
	Name string
}

func (w WorkloadIdentity) String() string {
	return w.Kind + "/" + w.Name
}

// WorkloadIdentityForPod resolves the stable workload identity for a pod
// using only data already present on the pod object (owner references,
// labels, node name), so it needs no API round-trips.
func WorkloadIdentityForPod(pod *v1.Pod) WorkloadIdentity {
	if pod == nil {
		return WorkloadIdentity{Kind: "pod", Name: "unknown"}
	}

	if owner := metav1.GetControllerOf(pod); owner != nil {
		switch owner.Kind {
		case "ReplicaSet":
			// Deployment-owned ReplicaSets are named "<deployment>-<pod-template-hash>".
			if hash := pod.Labels["pod-template-hash"]; hash != "" {
				if name, ok := strings.CutSuffix(owner.Name, "-"+hash); ok {
					return WorkloadIdentity{Kind: "deployment", Name: name}
				}
			}
			return WorkloadIdentity{Kind: "replicaset", Name: owner.Name}
		case "DaemonSet", "StatefulSet", "Job":
			return WorkloadIdentity{Kind: strings.ToLower(owner.Kind), Name: owner.Name}
		case "Node":
			// Static (mirror) pods are named "<manifest name>-<node name>".
			return WorkloadIdentity{Kind: "staticpod", Name: trimNodeSuffix(pod.Name, pod.Spec.NodeName)}
		default:
			return WorkloadIdentity{Kind: strings.ToLower(owner.Kind), Name: owner.Name}
		}
	}

	// Unowned per-node pods (guard pods, installer and revision-pruner pods)
	// embed the node name, which contains the per-run cluster ID; strip it.
	return WorkloadIdentity{Kind: "pod", Name: trimNodeSuffix(pod.Name, pod.Spec.NodeName)}
}

func trimNodeSuffix(podName, nodeName string) string {
	if nodeName == "" {
		return podName
	}
	if name, ok := strings.CutSuffix(podName, "-"+nodeName); ok {
		return name
	}
	return podName
}
