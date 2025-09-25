#!/bin/bash

# A script to build, deploy, and run the OpenShift scanner application.
#
# Usage: ./deploy.sh <junit-xml-output-path>
#
# This script will create the specified JUnit XML file.

if [ -z "$1" ]; then
    echo "Usage: $0 <junit-xml-output-path>"
    echo "e.g., $0 /path/to/artifacts/junit.xml"
    exit 1
fi

JUNIT_OUTPUT_PATH="$1"
JUNIT_OUTPUT_DIR=$(dirname "$JUNIT_OUTPUT_PATH")

# --- Configuration ---
APP_NAME="scanner-app"

# --- Get Current Project ---
CURRENT_PROJECT=$(oc project -q)
if [ -z "$CURRENT_PROJECT" ]; then
    echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
    echo "Error: Could not determine current OpenShift project."
    echo "Please set a project using 'oc project <project-name>'"
    echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
    exit 1
fi
echo "--> Operating in project: $CURRENT_PROJECT"

# --- CI/CD Environment Setup ---
echo "--> Artifacts will be stored in: $JUNIT_OUTPUT_DIR"
# Create artifact directories
mkdir -p "$JUNIT_OUTPUT_DIR"
check_error "Creating artifact directory"


# --- Functions ---

# Function to print a formatted header
print_header() {
    echo "========================================================================"
    echo "=> $1"
    echo "========================================================================"
}

# Function to check for errors and exit if one occurs
check_error() {
    # $? is the exit code of the last command
    if [ $? -ne 0 ]; then
        echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
        echo "An error occurred during: '$1'"
        echo "Exiting script."
        echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
        exit 1
    fi
}

# Function to clean up existing resources before starting
cleanup() {
    print_header "Step 0: Cleaning Up Previous Deployments"
    echo "--> Deleting existing resources for '$APP_NAME' in project '$CURRENT_PROJECT' (if they exist)..."
    oc delete deployment "$APP_NAME" -n "$CURRENT_PROJECT" --ignore-not-found=true
    oc delete service "$APP_NAME" -n "$CURRENT_PROJECT" --ignore-not-found=true
    echo "--> Deleting existing builds for '$APP_NAME'..."
    oc delete builds -l buildconfig="$APP_NAME" -n "$CURRENT_PROJECT" --ignore-not-found=true
    oc delete buildconfig "$APP_NAME" -n "$CURRENT_PROJECT" --ignore-not-found=true
    oc delete imagestream "$APP_NAME" -n "$CURRENT_PROJECT" --ignore-not-found=true
    oc delete secret pull-secret -n "$CURRENT_PROJECT" --ignore-not-found=true
    echo "--> Removing pod-exec-reader role from default service account..."
    oc adm policy remove-cluster-role-from-user pod-exec-reader -z default -n "$CURRENT_PROJECT" --ignore-not-found=true
    echo "--> Removing privileged SCC from default service account..."
    oc adm policy remove-scc-from-user privileged -z default -n "$CURRENT_PROJECT" --ignore-not-found=true
    echo "--> Deleting pod-exec-reader cluster role..."
    oc delete clusterrole pod-exec-reader --ignore-not-found=true
    echo "--> Deleting ingress-reader role and binding..."
    oc delete role ingress-reader -n openshift-ingress-operator --ignore-not-found=true
    oc delete rolebinding read-ingress-from-project -n openshift-ingress-operator --ignore-not-found=true
    echo "Cleanup complete."
}


# --- Main Script ---

# 0. Clean up any previous runs
cleanup

# 1. Build and Deploy the Scanner
print_header "Step 1: Building and Deploying the Scanner"

echo "--> Creating new build configuration..."
oc new-build --name="$APP_NAME" --strategy=docker --binary
check_error "oc new-build"

echo "--> Setting resource limits for the build..."
oc patch bc/"$APP_NAME" -p '{"spec":{"resources":{"limits":{"memory":"8Gi","ephemeral-storage":"8Gi"},"requests":{"memory":"4Gi","ephemeral-storage":"4Gi"}}}}'
check_error "oc patch resources"

echo "--> Starting the build (this may take a few minutes)..."
oc start-build "$APP_NAME" --from-dir=. --follow
check_error "oc start-build"

echo "--> Deploying the new application with privileged security context..."
# Create a privileged deployment instead of using oc new-app
cat <<EOF | oc apply -f -
apiVersion: apps/v1
kind: Deployment
metadata:
  name: $APP_NAME
  labels:
    app: $APP_NAME
spec:
  replicas: 1
  selector:
    matchLabels:
      deployment: $APP_NAME
  template:
    metadata:
      labels:
        deployment: $APP_NAME
    spec:
      serviceAccountName: default
      securityContext:
        runAsUser: 0
        fsGroup: 0
      containers:
      - name: scanner
        image: image-registry.openshift-image-registry.svc:5000/$CURRENT_PROJECT/$APP_NAME:latest
        command: ["sleep", "infinity"]
        securityContext:
          privileged: true
          runAsUser: 0
          allowPrivilegeEscalation: true
          capabilities:
            add:
            - SYS_ADMIN
            - NET_ADMIN
            - SYS_PTRACE
        volumeMounts:
        - name: host-root
          mountPath: /host
          readOnly: true
        env:
        - name: HOME
          value: /root
      volumes:
      - name: host-root
        hostPath:
          path: /
          type: Directory
EOF
check_error "Creating privileged deployment"

echo "--> Granting permissions to the service account..."
oc adm policy add-cluster-role-to-user cluster-reader -z default -n "$CURRENT_PROJECT"
check_error "Granting cluster-reader permissions"

echo "--> Creating Role and RoleBinding to read IngressController status..."
cat <<EOF | oc apply -f -
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: ingress-reader
  namespace: openshift-ingress-operator
rules:
- apiGroups: ["operator.openshift.io"]
  resources: ["ingresscontrollers"]
  verbs: ["get", "list", "watch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: read-ingress-from-project
  namespace: openshift-ingress-operator
subjects:
- kind: ServiceAccount
  name: default
  namespace: $CURRENT_PROJECT
roleRef:
  kind: Role
  name: ingress-reader
  apiGroup: rbac.authorization.k8s.io
EOF
check_error "Creating ingress-reader Role and RoleBinding"

echo "--> Copying global pull secret..."
oc get secret pull-secret -n openshift-config -o yaml | sed "s/namespace: .*/namespace: $CURRENT_PROJECT/" | oc apply -n "$CURRENT_PROJECT" -f -
check_error "Copying pull secret"

echo "--> Linking default service account to global pull secret..."
oc secrets link default pull-secret --for=pull -n "$CURRENT_PROJECT"
check_error "Linking pull secret"

echo "--> Registry authentication configured via pull-secret linkage"

echo "--> Creating ClusterRole for pod exec..."
cat <<EOF | oc apply -f -
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: pod-exec-reader
rules:
- apiGroups: [""]
  resources: ["pods/exec"]
  verbs: ["create"]
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get"]
EOF
check_error "Creating pod-exec-reader ClusterRole"

echo "--> Binding pod-exec-reader role to default service account..."
oc adm policy add-cluster-role-to-user pod-exec-reader -z default -n "$CURRENT_PROJECT"
check_error "Binding pod-exec-reader role"

echo "--> Adding privileged SCC to service account for podman operations..."
oc adm policy add-scc-to-user privileged -z default -n "$CURRENT_PROJECT"
check_error "Adding privileged SCC"

echo "--> Waiting for the deployment to become ready..."
oc wait --for=condition=available --timeout=300s deployment/"$APP_NAME" -n "$CURRENT_PROJECT"
check_error "Waiting for deployment"
echo "Scanner pod is now running."

# 2. Prepare and Run the Scan
print_header "Step 2: Preparing and Running the Scan"

echo "--> Getting the current scanner pod name..."

# Loop to wait for the pod to be available and get its name
POD_NAME=""
for i in {1..10}; do
    echo "--> Attempt $i: Looking for pod with label deployment=$APP_NAME..."
    POD_NAME=$(oc get pods -n "$CURRENT_PROJECT" -l deployment="$APP_NAME" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
    if [ -n "$POD_NAME" ]; then
        echo "    Found Pod Name: $POD_NAME"
        break
    fi
    echo "    Pod not found yet. Waiting 5 seconds..."
    sleep 5
done

if [ -z "$POD_NAME" ]; then
    echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
    echo "Error: Could not find a running pod for deployment '$APP_NAME' after several attempts."
    echo "Listing all pods in project '$CURRENT_PROJECT' for debugging:"
    oc get pods -n "$CURRENT_PROJECT" --show-labels
    echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
    exit 1
fi

echo "--> Executing the scan in the background inside the pod..."
# Define artifact paths inside the pod
SCAN_DATE=$(date +%Y%m%d)
POD_ARTIFACT_DIR="/tmp/artifacts"
POD_JUNIT_FILE="junit-tls-scan.xml"
POD_LOG_FILE="logs.log"

# Create artifact dir in pod
oc exec -n "$CURRENT_PROJECT" "$POD_NAME" -- mkdir -p "$POD_ARTIFACT_DIR"
check_error "Creating artifact dir in pod"

# The command is run in the background of the script, but synchronously inside the pod
oc exec -n "$CURRENT_PROJECT" "$POD_NAME" -- /usr/local/bin/tls-scanner \
    -all-pods \
    -junitxml "$POD_ARTIFACT_DIR/$POD_JUNIT_FILE" \
    -j 12
check_error "Executing scan"

print_header "Step 3: Retrieving and Displaying Results"

echo "--> Copying debug log from the pod..."
oc cp "$CURRENT_PROJECT/$POD_NAME:$POD_ARTIFACT_DIR/$POD_LOG_FILE" "$JUNIT_OUTPUT_DIR/logs.log"
check_error "Copying debug log from pod"

echo "--> Copying JUnit XML results from the pod..."
oc cp "$CURRENT_PROJECT/$POD_NAME:$POD_ARTIFACT_DIR/$POD_JUNIT_FILE" "$JUNIT_OUTPUT_PATH"
check_error "Copying JUnit XML results from pod"

echo "--> Copying scan error results from the pod (if they exist)..."
oc cp "$CURRENT_PROJECT/$POD_NAME:$POD_ARTIFACT_DIR/security-scan-${SCAN_DATE}_errors.csv" "$JUNIT_OUTPUT_DIR/security-scan-${SCAN_DATE}_errors.csv" 2>/dev/null || echo "   No scan errors file found (this is normal if no scan errors occurred)"

echo "--> Scan complete! Results available in $JUNIT_OUTPUT_DIR"
echo "   JUnit Report: $JUNIT_OUTPUT_PATH"
echo "   CSV Error Report: $JUNIT_OUTPUT_DIR/security-scan-$SCAN_DATE"_errors.csv" (if errors occurred)"
echo "   Debug Log: $JUNIT_OUTPUT_DIR/logs.log"
echo ""

