#!/bin/bash
# A script to build, deploy, and run the OpenShift scanner application.
#
# Usage: ./deploy.sh [action]
# Actions:
#   build          - Build the container image.
#   push           - Push the container image to a registry.
#   deploy         - Deploy the scanner as a Kubernetes Job.
#   cleanup        - Remove all scanner-related resources.
#   full-deploy    - Run build, push, and deploy actions.
#   (no action)    - Run a full-deploy and then cleanup.

# --- Configuration ---
APP_NAME="tls-scanner"
# Default image name, can be overridden by environment variable SCANNER_IMAGE
SCANNER_IMAGE=${SCANNER_IMAGE:-"quay.io/user/tls-scanner:latest"}
# Namespace to deploy to, can be overridden by NAMESPACE env var
NAMESPACE=${NAMESPACE:-$(oc project -q)}
JOB_TEMPLATE="scanner-job.yaml.template"
JOB_NAME="tls-scanner-job"

# --- Functions ---

# Function to print a formatted header
print_header() {
    echo "========================================================================"
    echo "=> $1"
    echo "========================================================================"
}

# Function to check for errors and exit if one occurs
check_error() {
    if [ $? -ne 0 ]; then
        echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
        echo "An error occurred during: '$1'"
        echo "Exiting script."
        echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
        exit 1
    fi
}

# Function to check for required commands
check_command() {
    if ! command -v "$1" &> /dev/null; then
        echo "Error: Required command '$1' is not installed or not in PATH."
        exit 1
    fi
}

build_image() {
    print_header "Step 1: Building Scanner Image"
    echo "--> Building image: ${SCANNER_IMAGE}"

    # Use 'docker' or 'podman' based on what's available
    BUILD_CMD="docker"
    if command -v podman &> /dev/null; then
        BUILD_CMD="podman"
    fi
    check_command $BUILD_CMD

    # Build the Go binary statically
    go build -o tls-scanner .
    check_error "Go build"

    $BUILD_CMD build -t "${SCANNER_IMAGE}" .
    check_error "Container image build"
    echo "--> Image build complete."
}

push_image() {
    print_header "Step 2: Pushing Scanner Image"
    echo "--> Pushing image: ${SCANNER_IMAGE}"
    
    # Use 'docker' or 'podman' based on what's available
    BUILD_CMD="docker"
    if command -v podman &> /dev/null; then
        BUILD_CMD="podman"
    fi
    check_command $BUILD_CMD

    $BUILD_CMD push "${SCANNER_IMAGE}"
    check_error "Image push"
    echo "--> Image push complete."
}

deploy_scanner_job() {
    print_header "Step 3: Deploying Scanner Job"
    check_command "oc"

    if [ -z "$NAMESPACE" ]; then
        echo "Error: Could not determine OpenShift project. Please set NAMESPACE or run 'oc project <name>'."
        exit 1
    fi
    echo "--> Deploying to namespace: $NAMESPACE"

    echo "--> Creating necessary RBAC permissions..."
    # Grant cluster-reader to the default service account in the target namespace
    oc adm policy add-cluster-role-to-user cluster-reader -z default -n "$NAMESPACE"
    check_error "Granting cluster-reader"
    
    # The pod exec role is necessary for detailed process scanning within pods
    oc adm policy add-scc-to-user privileged -z default -n "$NAMESPACE"
    check_error "Adding privileged SCC"

    echo "--> Creating additional RBAC permissions for cross-namespace resource access..."
cat <<EOF | oc apply -f -
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: tls-scanner-cross-namespace
rules:
- apiGroups:
  - ""
  resources:
  - pods/exec
  verbs:
  - create
- apiGroups:
  - operator.openshift.io
  resources:
  - ingresscontrollers
  verbs:
  - get
  - list
- apiGroups:
  - machineconfiguration.openshift.io
  resources:
  - kubeletconfigs
  verbs:
  - get
  - list
EOF
    check_error "Creating tls-scanner-cross-namespace ClusterRole"

    oc adm policy add-cluster-role-to-user tls-scanner-cross-namespace -z default -n "$NAMESPACE"
    check_error "Binding tls-scanner-cross-namespace ClusterRole"

    echo "--> Copying global pull secret to allow image pulls from CI registry..."
    oc get secret pull-secret -n openshift-config -o yaml | sed "s/namespace: .*/namespace: $NAMESPACE/" | oc apply -n "$NAMESPACE" -f -
    check_error "Copying pull secret"

    echo "--> Applying Job manifest from template: ${JOB_TEMPLATE}"
    if [ ! -f "$JOB_TEMPLATE" ]; then
        echo "Error: Job template file not found: ${JOB_TEMPLATE}"
        exit 1
    fi
    
    # Substitute environment variables in the template and apply it
    sed -e "s|\${SCANNER_IMAGE}|${SCANNER_IMAGE}|g" -e "s|\${NAMESPACE}|${NAMESPACE}|g" -e "s|\${JOB_NAME}|${JOB_NAME}|g" "$JOB_TEMPLATE" | oc apply -f -
    check_error "Applying Job manifest"

    echo "--> Scanner Job '${JOB_NAME}' deployed."
    echo "--> To monitor, run: oc logs -f job/tls-scanner-job -n ${NAMESPACE}"
    echo "--> Waiting for job to complete... (this may take a long time)"

    # Wait for the job to complete
}

cleanup() {
    print_header "Step 4: Cleaning Up Resources"
    check_command "oc"

    if [ -z "$NAMESPACE" ]; then
        echo "Warning: Could not determine OpenShift project for cleanup. Assuming 'default' or last-used."
    fi

    echo "--> Deleting Job '${JOB_NAME}' in namespace '${NAMESPACE}'..."
    oc delete job "$JOB_NAME" -n "$NAMESPACE" --ignore-not-found=true
    check_error "Deleting Job"

    echo "--> Removing RBAC permissions..."
    oc adm policy remove-cluster-role-from-user cluster-reader -z default -n "$NAMESPACE" || true
    oc adm policy remove-scc-from-user privileged -z default -n "$NAMESPACE" || true
    oc adm policy remove-cluster-role-from-user tls-scanner-cross-namespace -z default -n "$NAMESPACE" || true
    oc delete clusterrole tls-scanner-cross-namespace --ignore-not-found=true || true
    check_error "Removing RBAC permissions"

    echo "--> Deleting pull secret link..."
    oc secrets unlink default pull-secret -n "$NAMESPACE" || true

    echo "--> Cleanup complete."
}

# --- Main Script Logic ---

# Check for required commands at the start
check_command "go"
check_command "oc"

ACTION=${1:-"default"}

case "$ACTION" in
    build)
        build_image
        ;;
    push)
        push_image
        ;;
    deploy)
        deploy_scanner_job
        ;;
    cleanup)
        cleanup
        ;;
    full-deploy)
        build_image
        push_image
        deploy_scanner_job
        ;;
    default)
        build_image
        push_image
        deploy_scanner_job
        echo ""
        echo "--> Full deployment initiated. Manual cleanup will be required."
        echo "--> Run './deploy.sh cleanup' when scan is complete."
        ;;
    *)
        echo "Error: Unknown action '$ACTION'."
        echo "Usage: $0 [build|push|deploy|cleanup|full-deploy]"
        exit 1
        ;;
esac

