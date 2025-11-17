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
    check_command "envsubst"

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

    echo "--> Applying Job manifest from template: ${JOB_TEMPLATE}"
    if [ ! -f "$JOB_TEMPLATE" ]; then
        echo "Error: Job template file not found: ${JOB_TEMPLATE}"
        exit 1
    fi
    
    # Substitute environment variables in the template and apply it
    envsubst < "$JOB_TEMPLATE" | oc apply -f -
    check_error "Applying Job manifest"
    
    echo "--> Scanner Job '${JOB_NAME}' deployed."
    echo "--> To monitor, run: oc logs -f job/${JOB_NAME} -n ${NAMESPACE}"
    echo "--> To retrieve artifacts, wait for completion and then use 'oc cp'."
}

cleanup() {
    print_header "Step 4: Cleaning Up Resources"
    check_command "oc"

    if [ -z "$NAMESPACE" ]; then
        echo "Warning: Could not determine OpenShift project for cleanup. Assuming 'default' or last-used."
    fi

    echo "--> Deleting Job '${JOB_NAME}' in namespace '${NAMESPACE}'..."
    oc delete job "$JOB_NAME" -n "$NAMESPACE" --ignore-not-found=true

    echo "--> Removing RBAC permissions..."
    oc adm policy remove-cluster-role-from-user cluster-reader -z default -n "$NAMESPACE" --ignore-not-found=true
    oc adm policy remove-scc-from-user privileged -z default -n "$NAMESPACE" --ignore-not-found=true

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

