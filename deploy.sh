#!/bin/bash
# A script to build, deploy, and run the OpenShift scanner application.
#
# Usage: ./deploy.sh [--verbose] [action]
# Actions:
#   build           - Build the container image.
#   push            - Push the container image to a registry.
#   deploy          - Deploy the scanner as a Kubernetes Job.
#   cleanup         - Remove all scanner-related resources.
#   full-deploy     - Run build, push, and deploy actions.
#   test-tls-config - Test scanner by changing API Server TLS config and validating detection.
#   (no action)     - Run a full-deploy and then cleanup.
#
# Environment Variables:
#   DOCKERFILE       - Dockerfile to use (default: Dockerfile, use Dockerfile.local for local builds)
#   SCANNER_IMAGE    - Image name (default: quay.io/user/tls-scanner:latest)
#   NAMESPACE        - Target namespace (default: current oc project)
#   NAMESPACE_FILTER - Comma-separated namespace list to scan
#   LIMIT_IPS        - Limit number of IPs to scan (default: 0 = no limit)
#   SCANNER_CPU_REQUEST - CPU request for scanner pod (default: 500m; falls back to SCANNER_CPU if set)
#   SCANNER_CPU_LIMIT   - CPU limit for scanner pod (default: 4; falls back to SCANNER_CPU if set)
#   SCANNER_CPU      - (Deprecated) Sets both CPU request and limit if the vars above are unset
#   SCANNER_MEM_REQUEST - Memory request for scanner pod (default: 4Gi; falls back to SCANNER_MEM if set)
#   SCANNER_MEM_LIMIT   - Memory limit for scanner pod (default: 4Gi; falls back to SCANNER_MEM if set)
#   SCANNER_MEM      - (Deprecated) Sets both memory request and limit if the vars above are unset
#   SCANNER_PARALLEL - Parallel scan count (default: 4)
#   ARTIFACT_WAIT    - Seconds to keep pod alive after scan for artifact collection (default: 30, CI uses 300)
#   TLS_TEST_TIMEOUT - Timeout for cluster stabilization during TLS tests (default: 600)
#   STARTTLS_PORTS   - (Optional) STARTTLS protocol-to-port mapping (e.g., postgres=5432:6432,mysql=3306)

# --- Configuration ---
APP_NAME="tls-scanner"
# Default image name, can be overridden by environment variable SCANNER_IMAGE
SCANNER_IMAGE=${SCANNER_IMAGE:-"quay.io/user/tls-scanner:latest"}
# Namespace to deploy to, can be overridden by NAMESPACE env var
NAMESPACE=${NAMESPACE:-$(oc project -q)}

# JOB_TEMPLATE specifies the YAML file containing the template for the tls-scanner job invocation
JOB_TEMPLATE=${JOB_TEMPLATE_FILE:-"scanner-job.yaml.template"}

# SCAN_MODE options:
#   pod  - will query for the running pods' exposed TLS ports and scan them.
#   host - will run as a privileged container on the host, scan all open TCP ports, and check their TLS configuration.
SCAN_MODE=${SCAN_MODE:-"pod"}
JOB_NAME="tls-scanner-job"
LIMIT_IPS="${LIMIT_IPS:-0}"  # Limit number of IPs to scan (0 = no limit, useful for testing)
# Architectures to build container images for
BUILD_PLATFORMS="${BUILD_PLATFORMS:-linux/amd64,linux/arm64,linux/s390x,linux/ppc64le}"

# TLS test configuration
TLS_TEST_TIMEOUT=${TLS_TEST_TIMEOUT:-600}  # 10 minutes default, configurable
TLS_TEST_RESULTS_DIR="./tls-test-results"

# --- Functions ---

# Function to print a formatted header
print_header() {
    echo "========================================================================"
    echo "=> $1"
    echo "========================================================================"
}

# Function to check if a command exists
check_command() {
    if ! command -v $1 &> /dev/null; then
        echo "Error: Required command '$1' is not installed or not in PATH."
        exit 1
    fi
}

# Function to check the last command's exit status
check_error() {
    if [ $? -ne 0 ]; then
        echo "Error: $1 failed."
        exit 1
    fi
}

build_image() {
    print_header "Step 1: Building Container Image"
    check_command "podman" || check_command "docker"
    check_command "go"

    echo "--> Building Go binary..."
    GOOS=linux make build
    check_error "Go build"

    echo "--> Building container image: ${SCANNER_IMAGE}"
    DOCKERFILE="${DOCKERFILE:-Dockerfile}"
    echo "    Using Dockerfile: ${DOCKERFILE}"

    PLATFORMS="${BUILD_PLATFORMS}"
    if [ "$DOCKERFILE" = "Dockerfile.local" ]; then
        PLATFORMS="${TARGET_PLATFORM:-linux/amd64}"
    fi

    if command -v podman &> /dev/null; then
        podman build --platform ${PLATFORMS} -t ${SCANNER_IMAGE} -f ${DOCKERFILE} .
        check_error "Podman build"
    elif command -v docker &> /dev/null; then
        docker build --platform ${PLATFORMS} -t ${SCANNER_IMAGE} -f ${DOCKERFILE} .
        check_error "Docker build"
    fi
    echo "--> Image built: ${SCANNER_IMAGE}"
}

push_image() {
    print_header "Step 2: Pushing Container Image"
    check_command "podman" || check_command "docker"

    echo "--> Pushing container image: ${SCANNER_IMAGE}"
    if command -v podman &> /dev/null; then
        podman push ${SCANNER_IMAGE} --tls-verify=false
        check_error "Podman push"
    elif command -v docker &> /dev/null; then
        docker push ${SCANNER_IMAGE}
        check_error "Docker push"
    fi
    echo "--> Image pushed: ${SCANNER_IMAGE}"
}

deploy_scanner_job() {
    print_header "Step 3: Deploying Scanner Job"
    check_command "oc"

    if [ -z "$NAMESPACE" ]; then
        echo "Error: Could not determine OpenShift project. Please set NAMESPACE or run 'oc project <name>'."
        exit 1
    fi
    echo "--> Deploying to namespace: ${NAMESPACE}"

    echo "--> Ensuring 'default' ServiceAccount exists in namespace '${NAMESPACE}'..."
    oc get sa default -n "$NAMESPACE" &> /dev/null || oc create sa default -n "$NAMESPACE"
    check_error "Creating ServiceAccount"

    echo "--> Granting 'cluster-reader' ClusterRole to 'default' ServiceAccount..."
    oc adm policy add-cluster-role-to-user cluster-reader -z default -n "$NAMESPACE"
    check_error "Adding cluster-reader role"

    echo "--> Granting 'privileged' SCC to 'default' ServiceAccount..."
    oc adm policy add-scc-to-user privileged -z default -n "$NAMESPACE"
    check_error "Adding privileged SCC"

    echo "--> Creating ClusterRole 'tls-scanner-cross-namespace' for cross-namespace resource access..."
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

    echo "--> Binding 'tls-scanner-cross-namespace' ClusterRole to 'default' ServiceAccount..."
    oc adm policy add-cluster-role-to-user tls-scanner-cross-namespace -z default -n "$NAMESPACE"
    check_error "Binding tls-scanner-cross-namespace ClusterRole"

    # Only copy the global pull secret if this is NOT a MicroShift job (template doesn't contain 'microshift')
    # In MicroShift, we do NOT need to provide the tls-scanner pod access to the API server,
    # in MicroShift the tls-scanner scans the ports exposed by a binary that runs directly on the host, not inside containers.
    # Therefore, it's safe to skip pull secret and cluster API access when using the MicroShift template.
    if [[ "$SCAN_MODE" == "pod" ]]; then  

        echo "--> Copying global pull secret to allow image pulls from CI registry..."
        oc delete secret pull-secret -n "$NAMESPACE" --ignore-not-found=true
        oc get secret pull-secret -n openshift-config -o yaml | sed "s/namespace: .*/namespace: $NAMESPACE/" | oc apply -n "$NAMESPACE" -f -
        check_error "Copying pull secret"
        oc secrets link default pull-secret --for=pull -n "$NAMESPACE" 2>/dev/null || echo "    (pull-secret already linked to default SA)"
    fi

    echo "--> Applying Job manifest from template: ${JOB_TEMPLATE}"
    if [ ! -f "$JOB_TEMPLATE" ]; then
        echo "Error: Job template file not found: ${JOB_TEMPLATE}"
        exit 1
    fi
    echo "--> Deleting old Job '${JOB_NAME}' if it exists (to update immutable fields)..."
    oc delete job "$JOB_NAME" -n "$NAMESPACE" --ignore-not-found=true

    NAMESPACE_FILTER_ARG=""
    if [ -n "$NAMESPACE_FILTER" ]; then
        NAMESPACE_FILTER_ARG="--namespace-filter $(echo "${NAMESPACE_FILTER}" | tr -d ' ')"
    fi
    
    LIMIT_IPS_ARG=""
    if [ "$LIMIT_IPS" -gt 0 ] 2>/dev/null; then
        LIMIT_IPS_ARG="--limit-ips ${LIMIT_IPS}"
        echo "--> Limiting scan to first ${LIMIT_IPS} IPs (testing mode)"
    fi

    STARTTLS_PORTS_ARG=""
    if [ -n "$STARTTLS_PORTS" ]; then
        STARTTLS_PORTS_ARG="--starttls-ports $(echo "${STARTTLS_PORTS}" | tr -d ' ')"
    fi

    # SCANNER_CPU/SCANNER_MEM are deprecated but still honored as fallback
    # defaults for both request and limit when the split vars aren't
    # explicitly set, so that a lower CPU request (e.g. 500m) can get the
    # Pod scheduled while still allowing it to burst up to the higher limit.
    SCANNER_CPU_REQUEST="${SCANNER_CPU_REQUEST:-${SCANNER_CPU:-500m}}"
    SCANNER_CPU_LIMIT="${SCANNER_CPU_LIMIT:-${SCANNER_CPU:-4}}"
    SCANNER_MEM_REQUEST="${SCANNER_MEM_REQUEST:-${SCANNER_MEM:-4Gi}}"
    SCANNER_MEM_LIMIT="${SCANNER_MEM_LIMIT:-${SCANNER_MEM:-4Gi}}"
    SCANNER_PARALLEL="${SCANNER_PARALLEL:-4}"
    ARTIFACT_WAIT="${ARTIFACT_WAIT:-30}"

    # Render to a temp file first (rather than piping straight into `oc apply`)
    # so we can server-side dry-run it and catch template/resource mistakes
    # (e.g. inconsistent SCANNER_*_REQUEST/LIMIT values) before actually
    # applying anything.
    RENDERED_JOB=$(mktemp)
    check_error "Creating temp file for rendered Job manifest"
    # Use an EXIT trap (rather than RETURN) so the temp file is still cleaned
    # up if we exit early below (e.g. on a failed dry-run), not just on a
    # normal function return.
    trap 'rm -f "$RENDERED_JOB"' EXIT

    sed -e "s|\\\${SCANNER_IMAGE}|${SCANNER_IMAGE}|g" -e "s|\\\${NAMESPACE}|${NAMESPACE}|g" -e "s|\\\${JOB_NAME}|${JOB_NAME}|g" -e "s|\\\${NAMESPACE_FILTER_ARG}|${NAMESPACE_FILTER_ARG}|g" -e "s|\\\${LIMIT_IPS_ARG}|${LIMIT_IPS_ARG}|g" -e "s|\\\${STARTTLS_PORTS_ARG}|${STARTTLS_PORTS_ARG}|g" -e "s|\\\${SCANNER_CPU_REQUEST:-500m}|${SCANNER_CPU_REQUEST}|g" -e "s|\\\${SCANNER_CPU_LIMIT:-4}|${SCANNER_CPU_LIMIT}|g" -e "s|\\\${SCANNER_MEM_REQUEST:-4Gi}|${SCANNER_MEM_REQUEST}|g" -e "s|\\\${SCANNER_MEM_LIMIT:-4Gi}|${SCANNER_MEM_LIMIT}|g" -e "s|\\\${SCANNER_PARALLEL:-4}|${SCANNER_PARALLEL}|g" -e "s|\\\${ARTIFACT_WAIT:-300}|${ARTIFACT_WAIT}|g" "$JOB_TEMPLATE" > "$RENDERED_JOB"
    check_error "Rendering Job manifest"

    echo "--> Validating rendered Job manifest (server-side dry-run)..."
    if ! oc apply --dry-run=server -f "$RENDERED_JOB"; then
        echo "Error: Invalid Job manifest (check SCANNER_*_REQUEST/LIMIT values)"
        exit 1
    fi

    oc apply -f "$RENDERED_JOB"
    check_error "Applying Job manifest"

    echo "--> Scanner Job '${JOB_NAME}' deployed."
    
    echo "--> Waiting for scanner pod to be created and start running..."
    POD_RUNNING=false
    # Wait up to 10 minutes (60 * 10s) for the pod to start.
    for i in {1..60}; do
        POD_NAME=$(oc get pods -n "${NAMESPACE}" -l job-name=${JOB_NAME} -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
        if [ -z "$POD_NAME" ]; then
            echo "    Pod for job not created yet. Waiting... (${i}/60)"
            sleep 10
            continue
        fi

        POD_PHASE=$(oc get pod "${POD_NAME}" -n "${NAMESPACE}" -o jsonpath='{.status.phase}' 2>/dev/null || echo "Unknown")
        
        if [ "$POD_PHASE" = "Running" ]; then
            echo "--> Pod '${POD_NAME}' is now running."
            POD_RUNNING=true
            break
        elif [ "$POD_PHASE" = "Failed" ] || [ "$POD_PHASE" = "Error" ]; then
            echo "Error: Pod '${POD_NAME}' failed to start. Final phase: $POD_PHASE"
            echo "--- Describing failed pod for details ---"
            oc describe pod "${POD_NAME}" -n "${NAMESPACE}"
            echo "--- End of pod description ---"
            exit 1
        elif [ "$POD_PHASE" = "Succeeded" ]; then
             echo "--> Pod '${POD_NAME}' completed very quickly. Assuming success and proceeding to wait for job completion."
             POD_RUNNING=true
             break
        else
            echo "    Pod status is '${POD_PHASE}'. Waiting... (${i}/60)"
            # Check for common container-level waiting issues
            REASON=$(oc get pod "${POD_NAME}" -n "${NAMESPACE}" -o jsonpath='{.status.containerStatuses[0].state.waiting.reason}' 2>/dev/null)
            if [ -n "$REASON" ]; then
                 echo "    Container waiting reason: ${REASON}. This may indicate an image pull or configuration issue."
            fi
            
            # Check if pod is scheduled but not starting (potential node/kubelet issue)
            if [ $i -eq 30 ]; then  # After 5 minutes, check for node issues
                POD_SCHEDULED=$(oc get pod "${POD_NAME}" -n "${NAMESPACE}" -o jsonpath='{.status.conditions[?(@.type=="PodScheduled")].status}' 2>/dev/null)
                POD_NODE=$(oc get pod "${POD_NAME}" -n "${NAMESPACE}" -o jsonpath='{.spec.nodeName}' 2>/dev/null)
                if [ "$POD_SCHEDULED" = "True" ] && [ -n "$POD_NODE" ]; then
                    echo "    WARNING: Pod scheduled to node $POD_NODE but not starting after 5min. Checking node and events..."
                    oc get node "$POD_NODE" --no-headers 2>/dev/null | head -1 || echo "    Could not get node status"
                    echo "    Recent events for pod:"
                    oc get events -n "${NAMESPACE}" --field-selector involvedObject.name="${POD_NAME}" --sort-by='.lastTimestamp' 2>/dev/null | tail -5 || echo "    No events found"
                fi
            fi
            
            sleep 10
        fi
    done

    if ! $POD_RUNNING; then
        echo "Error: Pod did not start running within 10 minutes."
        if [ -n "$POD_NAME" ]; then
            echo "--- Describing non-running pod for details ---"
            oc describe pod "${POD_NAME}" -n "${NAMESPACE}"
            echo "--- End of pod description ---"
        else
            echo "--- No pod was created for the job. Describing job for details ---"
            oc describe job "${JOB_NAME}" -n "${NAMESPACE}"
            echo "--- End of job description ---"
        fi
        exit 1
    fi

    echo "--> Waiting for scanner to finish... (timeout: 4h)"

    POD_NAME=$(oc get pods -n "${NAMESPACE}" -l job-name=${JOB_NAME} -o jsonpath='{.items[0].metadata.name}')

    LOG_PID=""
    if [ "$VERBOSE" = true ]; then
        echo "--> Streaming pod logs (--verbose)..."
        oc logs -f "pod/${POD_NAME}" -n "${NAMESPACE}" 2>/dev/null &
        LOG_PID=$!
    else
        echo "--> To stream logs, rerun with --verbose or: oc logs -f pod/${POD_NAME} -n ${NAMESPACE}"
    fi

    START_TIME=$(date +%s)
    TIMEOUT=14400
    SCANNER_FINISHED=false

    while true; do
        CURRENT_TIME=$(date +%s)
        ELAPSED=$((CURRENT_TIME - START_TIME))

        if [ $ELAPSED -gt $TIMEOUT ]; then
            [ -n "$LOG_PID" ] && kill $LOG_PID 2>/dev/null || true
            echo "Error: Scanner did not complete within 4h timeout."
            exit 1
        fi

        if oc logs "pod/${POD_NAME}" -n "${NAMESPACE}" 2>/dev/null | grep -q "Scanner finished with exit code:"; then
            SCANNER_FINISHED=true
            sleep 2
            [ -n "$LOG_PID" ] && kill $LOG_PID 2>/dev/null || true
            echo ""
            echo "--> Scanner has finished. Copying artifacts while pod is still alive..."
            break
        fi

        POD_STATUS=$(oc get pod "${POD_NAME}" -n "${NAMESPACE}" -o jsonpath='{.status.phase}' 2>/dev/null)
        if [ "$POD_STATUS" = "Failed" ]; then
            [ -n "$LOG_PID" ] && kill $LOG_PID 2>/dev/null || true
            echo "Error: Scanner pod failed."
            exit 1
        fi

        sleep 5
    done
    
    # Copy artifacts while the pod is still running (during the 120-second sleep window)
    if [ "$SCANNER_FINISHED" = "true" ]; then
        echo "--> Copying artifacts from running pod..."
        mkdir -p ./artifacts
        
        # Give the scanner a moment to flush all files
        sleep 3
        
        # Copy files from the pod
        oc cp "${NAMESPACE}/${POD_NAME}:/artifacts/results.json" "./artifacts/results.json" 2>/dev/null || echo "Warning: Could not copy results.json"
        oc cp "${NAMESPACE}/${POD_NAME}:/artifacts/results.csv" "./artifacts/results.csv" 2>/dev/null || echo "Warning: Could not copy results.csv"
        oc cp "${NAMESPACE}/${POD_NAME}:/artifacts/scan.log" "./artifacts/scan.log" 2>/dev/null || echo "Warning: Could not copy scan.log"
        
        echo "--> Artifacts copied to ./artifacts directory."
        echo "--> Listing artifacts:"
        ls -lh ./artifacts/
    fi
    
    # Now wait for the job to complete
    echo "--> Waiting for job to complete... (timeout: 4h)"
    if ! oc wait --for=condition=complete "job/${JOB_NAME}" -n "${NAMESPACE}" --timeout=4h; then
        echo "Error: Job '${JOB_NAME}' did not complete within the 4h timeout."
        echo "--- Final job status ---"
        oc describe job "${JOB_NAME}" -n "${NAMESPACE}"
        exit 1
    fi
    
    echo "--> Job '${JOB_NAME}' completed successfully."
}

# --- TLS Test Helper Functions ---

# Wait for API server pods to be stable after TLS configuration changes
wait_for_api_server_stable() {
    local timeout=${1:-$TLS_TEST_TIMEOUT}
    local start_time=$(date +%s)
    local poll_interval=30
    
    echo "--> Waiting for API server to stabilize (timeout: ${timeout}s)..."
    
    while true; do
        local current_time=$(date +%s)
        local elapsed=$((current_time - start_time))
        
        if [ $elapsed -gt $timeout ]; then
            echo "Error: API server did not stabilize within ${timeout}s timeout."
            return 1
        fi
        
        # First, check if we can connect to the API at all
        if ! oc get nodes &>/dev/null; then
            echo "    API server not responding yet. Elapsed: ${elapsed}s. Waiting..."
            sleep $poll_interval
            continue
        fi
        
        # Check kube-apiserver pods in openshift-kube-apiserver namespace
        local kube_api_ready=$(oc get pods -n openshift-kube-apiserver -l app=openshift-kube-apiserver -o jsonpath='{.items[*].status.conditions[?(@.type=="Ready")].status}' 2>/dev/null | tr ' ' '\n' | grep -c "True" || echo "0")
        local kube_api_total=$(oc get pods -n openshift-kube-apiserver -l app=openshift-kube-apiserver --no-headers 2>/dev/null | wc -l || echo "0")
        
        # Check openshift-apiserver pods
        local ocp_api_ready=$(oc get pods -n openshift-apiserver -l app=openshift-apiserver -o jsonpath='{.items[*].status.conditions[?(@.type=="Ready")].status}' 2>/dev/null | tr ' ' '\n' | grep -c "True" || echo "0")
        local ocp_api_total=$(oc get pods -n openshift-apiserver -l app=openshift-apiserver --no-headers 2>/dev/null | wc -l || echo "0")
        
        echo "    API server status: kube-apiserver ${kube_api_ready}/${kube_api_total} ready, openshift-apiserver ${ocp_api_ready}/${ocp_api_total} ready. Elapsed: ${elapsed}s"
        
        # Consider stable if at least one pod is ready in each namespace
        if [ "$kube_api_ready" -gt 0 ] && [ "$ocp_api_ready" -gt 0 ]; then
            # Additional check: verify API server is responding properly
            if oc get apiserver cluster &>/dev/null; then
                echo "--> API server is stable and responding."
                return 0
            fi
        fi
        
        sleep $poll_interval
    done
}

# Get current API server TLS configuration and save to file
get_current_apiserver_tls_config() {
    local output_file="${1:-/tmp/apiserver-tls-config-backup.json}"
    
    echo "--> Saving current API Server TLS configuration to ${output_file}..."
    
    # Get the current tlsSecurityProfile spec
    local tls_config=$(oc get apiserver cluster -o jsonpath='{.spec.tlsSecurityProfile}' 2>/dev/null)
    
    if [ -z "$tls_config" ] || [ "$tls_config" = "null" ]; then
        echo "null" > "$output_file"
        echo "    Current config: Default (no custom TLS profile set)"
    else
        echo "$tls_config" > "$output_file"
        echo "    Current config saved: $tls_config"
    fi
    
    echo "$output_file"
}

# Set API server TLS configuration
set_apiserver_tls_config() {
    local config="$1"
    
    echo "--> Applying API Server TLS configuration..."
    echo "    Config: $config"
    
    if [ "$config" = "null" ] || [ -z "$config" ]; then
        # Remove the TLS security profile to restore default
        oc patch apiserver cluster --type=json -p='[{"op": "remove", "path": "/spec/tlsSecurityProfile"}]' 2>/dev/null || \
        oc patch apiserver cluster --type=merge -p '{"spec":{"tlsSecurityProfile":null}}'
    else
        # Apply the specified TLS configuration
        oc patch apiserver cluster --type=merge -p "{\"spec\":{\"tlsSecurityProfile\":$config}}"
    fi
    
    if [ $? -eq 0 ]; then
        echo "    TLS configuration applied successfully."
        return 0
    else
        echo "Error: Failed to apply TLS configuration."
        return 1
    fi
}

# Verify scan results contain only expected TLS version and cipher
verify_scan_results() {
    local results_file="$1"
    local expected_version="${2:-TLSv1.2}"
    local expected_cipher="${3:-ECDHE-RSA-AES128-GCM-SHA256}"
    
    echo "--> Verifying scan results from ${results_file}..."
    
    if [ ! -f "$results_file" ]; then
        echo "Error: Results file not found: $results_file"
        return 1
    fi
    
    # Check if jq is available
    if ! command -v jq &>/dev/null; then
        echo "Error: jq is required for result verification but not found."
        return 1
    fi
    
    local validation_passed=true
    local error_messages=""
    
    # Extract all TLS versions and ciphers from API server related scans
    # Look at all port results that have TLS information
    local tls_data=$(jq -r '
        .ip_results[]? | 
        select(.port_results != null) | 
        .port_results[]? | 
        select(.tls_versions != null and (.tls_versions | length) > 0) |
        {versions: .tls_versions, ciphers: .tls_ciphers}
    ' "$results_file" 2>/dev/null)
    
    if [ -z "$tls_data" ]; then
        echo "Warning: No TLS data found in scan results."
        echo "    This may indicate the scan did not detect any TLS-enabled services."
        # Check if there are any results at all
        local total_ips=$(jq -r '.scanned_ips // 0' "$results_file" 2>/dev/null)
        echo "    Total IPs scanned: $total_ips"
        return 1
    fi
    
    echo "    Found TLS data in scan results. Validating..."
    
    # Check TLS versions - should only contain TLSv1.3
    local versions=$(jq -r '
        [.ip_results[]?.port_results[]? | 
         select(.tls_versions != null) | 
         .tls_versions[]?] | unique | .[]
    ' "$results_file" 2>/dev/null)
    
    echo "    Detected TLS versions: $versions"
    
    # Validate versions
    local version_count=0
    local invalid_versions=""
    while IFS= read -r version; do
        [ -z "$version" ] && continue
        version_count=$((version_count + 1))
        if [ "$version" != "$expected_version" ]; then
            invalid_versions="$invalid_versions $version"
            validation_passed=false
        fi
    done <<< "$versions"
    
    if [ -n "$invalid_versions" ]; then
        error_messages="${error_messages}Unexpected TLS versions found:${invalid_versions}\n"
    fi
    
    if [ $version_count -eq 0 ]; then
        echo "Warning: No TLS versions detected in results."
        validation_passed=false
        error_messages="${error_messages}No TLS versions detected.\n"
    elif echo "$versions" | grep -q "$expected_version"; then
        echo "    [PASS] Expected TLS version '$expected_version' detected."
    else
        echo "    [FAIL] Expected TLS version '$expected_version' NOT detected."
        validation_passed=false
    fi
    
    # Check ciphers - should only contain TLS_AES_128_GCM_SHA256
    # Note: nmap may report it as TLS_AKE_WITH_AES_128_GCM_SHA256 for TLS 1.3
    local ciphers=$(jq -r '
        [.ip_results[]?.port_results[]? | 
         select(.tls_ciphers != null) | 
         .tls_ciphers[]?] | unique | .[]
    ' "$results_file" 2>/dev/null)
    
    echo "    Detected ciphers: $ciphers"
    
    # Validate ciphers - accept both IANA and OpenSSL naming conventions
    local cipher_count=0
    local invalid_ciphers=""
    local valid_cipher_found=false
    while IFS= read -r cipher; do
        [ -z "$cipher" ] && continue
        cipher_count=$((cipher_count + 1))
        # Accept variations of the expected cipher name (IANA and OpenSSL formats)
        # ECDHE-RSA-AES128-GCM-SHA256 = TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        if [[ "$cipher" == *"$expected_cipher"* ]] || \
           [[ "$cipher" == *"ECDHE"*"RSA"*"AES"*"128"*"GCM"* ]] || \
           [[ "$cipher" == *"AES_128_GCM_SHA256"* ]]; then
            valid_cipher_found=true
        else
            invalid_ciphers="$invalid_ciphers $cipher"
            validation_passed=false
        fi
    done <<< "$ciphers"
    
    if [ -n "$invalid_ciphers" ]; then
        error_messages="${error_messages}Unexpected ciphers found:${invalid_ciphers}\n"
    fi
    
    if [ $cipher_count -eq 0 ]; then
        echo "Warning: No ciphers detected in results."
        validation_passed=false
        error_messages="${error_messages}No ciphers detected.\n"
    elif [ "$valid_cipher_found" = true ]; then
        echo "    [PASS] Expected cipher (containing 'AES_128_GCM_SHA256') detected."
    else
        echo "    [FAIL] Expected cipher NOT detected."
        validation_passed=false
    fi
    
    # Print summary
    echo ""
    if [ "$validation_passed" = true ]; then
        echo "==> VALIDATION PASSED: Scan correctly detected TLS 1.3 with AES_128_GCM_SHA256 cipher."
        return 0
    else
        echo "==> VALIDATION FAILED:"
        echo -e "$error_messages"
        return 1
    fi
}

# Main TLS configuration test function
test_tls_configuration() {
    print_header "TLS Configuration Test"
    
    # Check prerequisites
    check_command "oc"
    check_command "jq"
    
    echo "--> Test configuration:"
    echo "    Timeout: ${TLS_TEST_TIMEOUT}s"
    echo "    Results directory: ${TLS_TEST_RESULTS_DIR}"
    echo "    Namespace filter: ${NAMESPACE_FILTER:-openshift-kube-apiserver,openshift-apiserver (default)}"
    echo ""
    
    # Create results directory
    mkdir -p "${TLS_TEST_RESULTS_DIR}"
    
    # Save original configuration
    local original_config_file="${TLS_TEST_RESULTS_DIR}/original-tls-config.json"
    get_current_apiserver_tls_config "$original_config_file"
    local original_config=$(cat "$original_config_file")
    
    # Set up trap to restore configuration on exit/error
    trap 'echo ""; echo "==> Restoring original TLS configuration due to interruption..."; set_apiserver_tls_config "$original_config"; wait_for_api_server_stable || true; exit 1' INT TERM
    
    local test_passed=false
    
    # Build and push the scanner image first
    echo ""
    print_header "Phase 0: Building Scanner Image"
    build_image
    push_image
    
    # Phase 1: Apply custom TLS configuration
    echo ""
    print_header "Phase 1: Custom TLS Configuration Test"
    
    # Define custom TLS config: TLS 1.2 with restricted cipher set
    # Note: TLS 1.3 ciphers are not configurable per TLS 1.3 spec, so we test with TLS 1.2
    local custom_config='{"type":"Custom","custom":{"ciphers":["ECDHE-RSA-AES128-GCM-SHA256"],"minTLSVersion":"VersionTLS12"}}'
    
    echo "--> Applying custom TLS 1.2 configuration..."
    echo "    Cipher: ECDHE-RSA-AES128-GCM-SHA256 (TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256)"
    echo "    Min TLS Version: TLS 1.2"
    echo "    Note: TLS 1.3 ciphers are not configurable per TLS 1.3 specification"
    
    if ! set_apiserver_tls_config "$custom_config"; then
        echo "Error: Failed to apply custom TLS configuration."
        set_apiserver_tls_config "$original_config"
        exit 1
    fi
    
    echo ""
    echo "--> Waiting for API server to restart with new TLS configuration..."
    if ! wait_for_api_server_stable "$TLS_TEST_TIMEOUT"; then
        echo "Error: API server did not stabilize after TLS configuration change."
        echo "--> Restoring original configuration..."
        set_apiserver_tls_config "$original_config"
        wait_for_api_server_stable || true
        exit 1
    fi
    
    # Run the scanner targeting API server namespaces (or user-specified namespace)
    echo ""
    echo "--> Running scanner to detect TLS configuration..."
    
    # Use user-provided namespace filter, or default to API server namespaces
    if [ -z "$NAMESPACE_FILTER" ]; then
        NAMESPACE_FILTER="openshift-kube-apiserver,openshift-apiserver"
        echo "    Using default namespace filter: ${NAMESPACE_FILTER}"
    else
        echo "    Using custom namespace filter: ${NAMESPACE_FILTER}"
    fi
    
    # Deploy and run the scanner
    deploy_scanner_job
    
    # Copy results to test results directory
    echo "--> Copying scan results to ${TLS_TEST_RESULTS_DIR}/custom-tls-scan/..."
    mkdir -p "${TLS_TEST_RESULTS_DIR}/custom-tls-scan"
    cp -r ./artifacts/* "${TLS_TEST_RESULTS_DIR}/custom-tls-scan/" 2>/dev/null || true
    
    # Verify the scan results
    echo ""
    print_header "Phase 2: Validating Scan Results"
    
    if verify_scan_results "${TLS_TEST_RESULTS_DIR}/custom-tls-scan/results.json"; then
        test_passed=true
    else
        test_passed=false
    fi
    
    # Phase 3: Restore original configuration
    echo ""
    print_header "Phase 3: Restoring Original Configuration"
    
    echo "--> Restoring original TLS configuration..."
    if ! set_apiserver_tls_config "$original_config"; then
        echo "Warning: Failed to restore original TLS configuration."
        echo "    You may need to manually restore the configuration."
    fi
    
    echo "--> Waiting for API server to stabilize..."
    wait_for_api_server_stable || echo "Warning: API server may not have fully stabilized."
    
    # Clean up the scanner job
    echo "--> Cleaning up scanner job..."
    oc delete job "$JOB_NAME" -n "$NAMESPACE" --ignore-not-found=true
    
    # Remove trap
    trap - INT TERM
    
    # Print final summary
    echo ""
    print_header "Test Summary"
    
    echo "Results saved to: ${TLS_TEST_RESULTS_DIR}/custom-tls-scan/"
    echo ""
    
    if [ "$test_passed" = true ]; then
        echo "========================================"
        echo "==>  TLS CONFIGURATION TEST: PASSED  <=="
        echo "========================================"
        echo ""
        echo "The scanner correctly detected:"
        echo "  - TLS version: TLSv1.2"
        echo "  - Cipher: ECDHE-RSA-AES128-GCM-SHA256"
        exit 0
    else
        echo "========================================"
        echo "==>  TLS CONFIGURATION TEST: FAILED  <=="
        echo "========================================"
        echo ""
        echo "The scanner did not detect the expected TLS configuration."
        echo "Check the results in: ${TLS_TEST_RESULTS_DIR}/custom-tls-scan/"
        exit 1
    fi
}

cleanup() {
    print_header "Step 4: Cleaning Up"
    check_command "oc"

    echo "--> Removing ClusterRoleBinding for 'cluster-reader'..."
    oc adm policy remove-cluster-role-from-user cluster-reader -z default -n "$NAMESPACE" || true
    echo "--> Removing ClusterRoleBinding for 'tls-scanner-cross-namespace'..."
    oc adm policy remove-cluster-role-from-user tls-scanner-cross-namespace -z default -n "$NAMESPACE" || true
    echo "--> Removing SCC 'privileged' from ServiceAccount..."
    oc adm policy remove-scc-from-user privileged -z default -n "$NAMESPACE" || true
    echo "--> Deleting ClusterRole 'tls-scanner-cross-namespace'..."
    oc delete clusterrole tls-scanner-cross-namespace --ignore-not-found=true
    echo "--> Deleting Job '${JOB_NAME}'..."
    oc delete job "$JOB_NAME" -n "$NAMESPACE" --ignore-not-found=true
    echo "--> Deleting copied pull secret..."
    oc delete secret pull-secret -n "$NAMESPACE" --ignore-not-found=true
    
    echo "--> Cleanup complete."
}

# --- Main Logic ---

NAMESPACE_FILTER="${NAMESPACE_FILTER:-}"
VERBOSE=false
POSITIONAL_ARGS=()

while [[ $# -gt 0 ]]; do
  case $1 in
    -n|--namespace-filter)
      NAMESPACE_FILTER="$2"
      shift
      shift
      ;;
    --limit-ips)
      LIMIT_IPS="$2"
      shift
      shift
      ;;
    -v|--verbose)
      VERBOSE=true
      shift
      ;;
    *)
      POSITIONAL_ARGS+=("$1")
      shift
      ;;
  esac
done

set -- "${POSITIONAL_ARGS[@]}"

ACTION=$1

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
    test-tls-config)
        test_tls_configuration
        ;;
    *)
        echo "No action specified, running full-deploy and cleanup."
        build_image
        push_image
        deploy_scanner_job
        cleanup
        ;;
esac
