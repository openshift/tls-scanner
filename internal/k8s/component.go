package k8s

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func (c *Client) GetOpenshiftComponentFromImage(image string) (*OpenshiftComponent, error) {
	slog.Debug("analyzing openshift image", "image", image)

	component := c.parseOpenshiftComponentFromImageRef(image)
	if component != nil {
		slog.Debug("parsed component info from image", "image", image, "component", component.Component)
		return component, nil
	}

	slog.Debug("gathering component info from cluster metadata", "image", image)
	return c.getComponentFromClusterMetadata(image)
}

// GetOpenshiftComponentFromPod extracts component information from a pod,
// preferring pod labels for the component name but using image metadata for
// source location and maintainer information.
func (c *Client) GetOpenshiftComponentFromPod(pod v1.Pod) (*OpenshiftComponent, error) {
	if len(pod.Spec.Containers) == 0 {
		return nil, fmt.Errorf("pod has no containers")
	}

	image := pod.Spec.Containers[0].Image
	container := pod.Spec.Containers[0]

	// Start with locally available pod data - no API calls needed
	component := &OpenshiftComponent{
		Component:           c.extractComponentFromPod(pod, container),
		MaintainerComponent: c.extractMaintainerFromPod(pod),
		IsBundle:            false,
	}

	// Try to enhance with image metadata (source location)
	// This attempts fast image reference parsing first, avoiding cluster-wide searches
	imageComponent := c.parseOpenshiftComponentFromImageRef(image)
	if imageComponent != nil {
		component.SourceLocation = imageComponent.SourceLocation
	} else {
		// Fall back to simple registry extraction
		component.SourceLocation = c.extractRegistryFromImage(image)
	}

	return component, nil
}

func (c *Client) parseOpenshiftComponentFromImageRef(image string) *OpenshiftComponent {
	if strings.Contains(image, "quay.io/openshift-release-dev") {
		component := &OpenshiftComponent{
			SourceLocation:      "quay.io/openshift-release-dev",
			MaintainerComponent: "openshift",
			IsBundle:            false,
		}

		if strings.Contains(image, "oauth-openshift") {
			component.Component = "oauth-openshift"
		} else if strings.Contains(image, "apiserver") {
			component.Component = "openshift-apiserver"
		} else if strings.Contains(image, "controller-manager") {
			component.Component = "openshift-controller-manager"
		} else {
			component.Component = "openshift-component"
		}

		return component
	}

	if strings.Contains(image, "image-registry.openshift-image-registry.svc") {
		parts := strings.Split(image, "/")
		if len(parts) >= 3 {
			return &OpenshiftComponent{
				Component:           parts[len(parts)-1],
				SourceLocation:      "internal-registry",
				MaintainerComponent: "user",
				IsBundle:            false,
			}
		}
	}

	if strings.Contains(image, "quay.io") || strings.Contains(image, "registry.redhat.com") {
		return &OpenshiftComponent{
			Component:           c.extractComponentNameFromImage(image),
			SourceLocation:      c.extractRegistryFromImage(image),
			MaintainerComponent: "redhat",
			IsBundle:            false,
		}
	}

	return nil
}

func (c *Client) getComponentFromClusterMetadata(image string) (*OpenshiftComponent, error) {
	slog.Debug("searching cluster for pods using image", "image", image)

	pods, err := c.clientset.CoreV1().Pods("").List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list pods for image metadata: %v", err)
	}

	for _, pod := range pods.Items {
		for _, container := range pod.Spec.Containers {
			if container.Image == image {
				component := &OpenshiftComponent{
					Component:           c.extractComponentFromPod(pod, container),
					SourceLocation:      c.extractRegistryFromImage(image),
					MaintainerComponent: c.extractMaintainerFromPod(pod),
					IsBundle:            false,
				}
				return component, nil
			}
		}
	}

	return &OpenshiftComponent{
		Component:           c.extractComponentNameFromImage(image),
		SourceLocation:      "unknown",
		MaintainerComponent: "unknown",
		IsBundle:            false,
	}, nil
}


func (c *Client) extractComponentNameFromImage(image string) string {
	parts := strings.Split(image, "/")
	if len(parts) > 0 {
		imageName := parts[len(parts)-1]
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

func (c *Client) extractRegistryFromImage(image string) string {
	if strings.Contains(image, "quay.io") {
		return "quay.io"
	} else if strings.Contains(image, "registry.redhat.com") {
		return "registry.redhat.com"
	} else if strings.Contains(image, "image-registry.openshift-image-registry.svc") {
		return "internal-registry"
	}
	return strings.Split(image, "/")[0]
}

// extractComponentFromPod returns a component name for a pod based on the following order
// of precedence:
//   1. label named 'app' 
//   2. label named 'component'
//   3. label named 'app.kubernetes.io/name'
//   4. container.Name
//   5. name determined from container.Image 
func (c *Client) extractComponentFromPod(pod v1.Pod, container v1.Container) string {
	if component, exists := pod.Labels["app"]; exists {
		return component
	}
	if component, exists := pod.Labels["component"]; exists {
		return component
	}
	if component, exists := pod.Labels["app.kubernetes.io/name"]; exists {
		return component
	}
	if container.Name != "" {
		return container.Name
	}
	return c.extractComponentNameFromImage(container.Image)
}

func (c *Client) extractMaintainerFromPod(pod v1.Pod) string {
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
