package k8s

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestExtractComponentNameFromImage(t *testing.T) {
	t.Parallel()

	c := newTestClient()
	tests := []struct {
		image string
		want  string
	}{
		{"quay.io/openshift/router:v4.18", "router"},
		{"quay.io/openshift/router@sha256:abc123", "router"},
		{"quay.io/openshift/router", "router"},
		{"registry.redhat.com/openshift4/ose-cli:latest", "ose-cli"},
		{"nginx", "nginx"},
		{"docker.io/library/nginx:1.25", "nginx"},
	}

	for _, tt := range tests {
		t.Run(tt.image, func(t *testing.T) {
			t.Parallel()
			got := c.extractComponentNameFromImage(tt.image)
			if got != tt.want {
				t.Errorf("extractComponentNameFromImage(%q) = %q, want %q", tt.image, got, tt.want)
			}
		})
	}
}

func TestExtractRegistryFromImage(t *testing.T) {
	t.Parallel()

	c := newTestClient()
	tests := []struct {
		image string
		want  string
	}{
		{"quay.io/openshift/router:v4.18", "quay.io"},
		{"registry.redhat.com/openshift4/ose-cli", "registry.redhat.com"},
		{"image-registry.openshift-image-registry.svc:5000/ns/img", "internal-registry"},
		{"docker.io/library/nginx", "docker.io"},
		{"gcr.io/project/image", "gcr.io"},
	}

	for _, tt := range tests {
		t.Run(tt.image, func(t *testing.T) {
			t.Parallel()
			got := c.extractRegistryFromImage(tt.image)
			if got != tt.want {
				t.Errorf("extractRegistryFromImage(%q) = %q, want %q", tt.image, got, tt.want)
			}
		})
	}
}

func TestParseOpenshiftComponentFromImageRef(t *testing.T) {
	t.Parallel()

	c := newTestClient()
	tests := []struct {
		name      string
		image     string
		wantNil   bool
		wantComp  string
		wantMaint string
	}{
		{
			name:      "oauth",
			image:     "quay.io/openshift-release-dev/ocp-v4.0-art-dev:oauth-openshift",
			wantComp:  "oauth-openshift",
			wantMaint: "openshift",
		},
		{
			name:      "apiserver",
			image:     "quay.io/openshift-release-dev/ocp-v4.0-art-dev:apiserver",
			wantComp:  "openshift-apiserver",
			wantMaint: "openshift",
		},
		{
			name:      "controller-manager",
			image:     "quay.io/openshift-release-dev/ocp-v4.0-art-dev:controller-manager",
			wantComp:  "openshift-controller-manager",
			wantMaint: "openshift",
		},
		{
			name:      "generic openshift-release-dev",
			image:     "quay.io/openshift-release-dev/ocp-v4.0-art-dev:etcd",
			wantComp:  "openshift-component",
			wantMaint: "openshift",
		},
		{
			name:      "internal registry",
			image:     "image-registry.openshift-image-registry.svc:5000/openshift/origin-router:latest",
			wantComp:  "origin-router:latest",
			wantMaint: "user",
		},
		{
			name:      "quay.io non-release-dev",
			image:     "quay.io/coreos/etcd:v3.5.0",
			wantComp:  "etcd",
			wantMaint: "redhat",
		},
		{
			name:      "registry.redhat.com",
			image:     "registry.redhat.com/openshift4/ose-cli:v4.18",
			wantComp:  "ose-cli",
			wantMaint: "redhat",
		},
		{
			name:    "unrecognized registry",
			image:   "docker.io/library/nginx:1.25",
			wantNil: true,
		},
		{
			name:    "no registry prefix",
			image:   "nginx:latest",
			wantNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := c.parseOpenshiftComponentFromImageRef(tt.image)
			if tt.wantNil {
				if got != nil {
					t.Errorf("expected nil for %q, got %+v", tt.image, got)
				}
				return
			}
			if got == nil {
				t.Fatalf("expected non-nil for %q", tt.image)
			}
			if got.Component != tt.wantComp {
				t.Errorf("Component = %q, want %q", got.Component, tt.wantComp)
			}
			if got.MaintainerComponent != tt.wantMaint {
				t.Errorf("MaintainerComponent = %q, want %q", got.MaintainerComponent, tt.wantMaint)
			}
		})
	}
}

func TestExtractComponentFromPod(t *testing.T) {
	t.Parallel()

	c := newTestClient()
	tests := []struct {
		name      string
		labels    map[string]string
		container corev1.Container
		want      string
	}{
		{
			name:      "app label",
			labels:    map[string]string{"app": "my-app"},
			container: corev1.Container{Name: "ctr", Image: "quay.io/x/y:z"},
			want:      "my-app",
		},
		{
			name:      "component label",
			labels:    map[string]string{"component": "my-component"},
			container: corev1.Container{Name: "ctr", Image: "quay.io/x/y:z"},
			want:      "my-component",
		},
		{
			name:      "app.kubernetes.io/name label",
			labels:    map[string]string{"app.kubernetes.io/name": "k8s-app"},
			container: corev1.Container{Name: "ctr", Image: "quay.io/x/y:z"},
			want:      "k8s-app",
		},
		{
			name:      "app label takes precedence over component",
			labels:    map[string]string{"app": "winner", "component": "loser"},
			container: corev1.Container{Name: "ctr"},
			want:      "winner",
		},
		{
			name:      "falls back to container name",
			labels:    map[string]string{},
			container: corev1.Container{Name: "my-container", Image: "nginx"},
			want:      "my-container",
		},
		{
			name:      "falls back to image name",
			labels:    map[string]string{},
			container: corev1.Container{Name: "", Image: "quay.io/org/my-image:v1"},
			want:      "my-image",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			pod := corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{Labels: tt.labels},
			}
			got := c.extractComponentFromPod(pod, tt.container)
			if got != tt.want {
				t.Errorf("extractComponentFromPod() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestExtractMaintainerFromPod(t *testing.T) {
	t.Parallel()

	c := newTestClient()
	tests := []struct {
		name      string
		namespace string
		labels    map[string]string
		want      string
	}{
		{"openshift namespace", "openshift-apiserver", nil, "openshift"},
		{"kube namespace", "kube-system", nil, "kubernetes"},
		{"maintainer label", "default", map[string]string{"maintainer": "team-x"}, "team-x"},
		{"unknown", "default", nil, "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			pod := corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: tt.namespace,
					Labels:    tt.labels,
				},
			}
			got := c.extractMaintainerFromPod(pod)
			if got != tt.want {
				t.Errorf("extractMaintainerFromPod() = %q, want %q", got, tt.want)
			}
		})
	}
}
