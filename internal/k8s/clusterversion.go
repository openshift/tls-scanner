package k8s

import (
	"context"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ClusterVersionInfo is the OpenShift payload identity useful as an attestation subject.
type ClusterVersionInfo struct {
	Version string `json:"version"`
	Image   string `json:"image"`
}

// GetClusterVersionInfo returns desired version and release image from clusterversion/cluster.
// Returns an error when the OpenShift config API is unavailable (e.g. plain Kubernetes).
func (c *Client) GetClusterVersionInfo() (*ClusterVersionInfo, error) {
	if c == nil || c.configClient == nil {
		return nil, fmt.Errorf("openshift config client not available")
	}
	cv, err := c.configClient.ConfigV1().ClusterVersions().Get(context.TODO(), "cluster", metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("get clusterversion/cluster: %w", err)
	}
	return &ClusterVersionInfo{
		Version: cv.Status.Desired.Version,
		Image:   cv.Status.Desired.Image,
	}, nil
}
