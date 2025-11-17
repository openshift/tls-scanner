# tls-scanner

A network security scanner for OpenShift/Kubernetes clusters that combines nmap port scanning with SSL/TLS cipher enumeration and OpenShift component analysis.

## Prerequisites

- **Go environment** - For building the scanner binary.
- **Container tool** - Docker or Podman for building and pushing the scanner image.
- **OpenShift/Kubernetes cluster access** - `oc` or `kubectl` configured to point to your target cluster.
- **Sufficient privileges** - Permissions to create Jobs, and grant `cluster-reader` and `privileged` SCC to a ServiceAccount.

## Installation & Usage

The scanner is designed to be run from within the cluster it is scanning. This is the most reliable way to ensure network access to all pods. The included `deploy.sh` script automates the build and deployment process.

### CI/CD Workflow (Recommended)

This is the recommended approach for automated scanning in an ephemeral test environment.

#### 1. Configure Environment

Set these environment variables in your CI job:

- `SCANNER_IMAGE`: The full tag of the image to build and push (e.g., `quay.io/my-org/tls-scanner:latest`).
- `NAMESPACE`: The OpenShift/Kubernetes namespace to run the scan in (e.g., `scanner-project`).
- `KUBECONFIG`: Path to the kubeconfig file for the ephemeral test cluster.

#### 2. Build and Push the Image

Your CI pipeline needs to be authenticated with your container registry.

```bash
# Build the binary and container image
./deploy.sh build

# Push the image to your registry
./deploy.sh push
```

#### 3. Deploy the Scan Job

This step creates the necessary RBAC permissions and deploys a Kubernetes Job into the ephemeral cluster.

```bash
./deploy.sh deploy
```

#### 4. Wait for Completion and Collect Results

The CI job must wait for the Kubernetes Job to complete and then copy the artifacts out.

```bash
# Wait for the job to finish (adjust timeout as needed)
kubectl wait --for=condition=complete job/tls-scanner-job -n "$NAMESPACE" --timeout=15m

# Get the name of the pod created by the job
POD_NAME=$(kubectl get pods -n "$NAMESPACE" -l job-name=tls-scanner-job -o jsonpath='{.items[0].metadata.name}')

# Create a local directory for artifacts
mkdir -p ./artifacts

# Copy all result files from the pod
kubectl cp "${NAMESPACE}/${POD_NAME}:/artifacts/." "./artifacts/"
```

Your `./artifacts` directory will now contain `results.json`, `results.csv`, and `scan.log`.

#### 5. Cleanup

Remove the scanner Job and associated RBAC permissions from the cluster.

```bash
./deploy.sh cleanup
```

### Manual Usage

You can also run the steps manually.

1.  **Build the image:** `export SCANNER_IMAGE="your-registry/image:tag"` and run `./deploy.sh build`.
2.  **Push the image:** `./deploy.sh push`.
3.  **Deploy the job:** `export NAMESPACE="your-namespace"` and run `./deploy.sh deploy`.
4.  **Monitor and retrieve results** as shown in the CI workflow.
5.  **Clean up** with `./deploy.sh cleanup`.

### `deploy.sh` Script Actions

-   `build`: Builds the `tls-scanner` binary and container image.
-   `push`: Pushes the container image to the registry specified by `$SCANNER_IMAGE`.
-   `deploy`: Deploys the scanner Kubernetes Job to the cluster specified by `$KUBECONFIG` and `$NAMESPACE`.
-   `cleanup`: Removes the scanner Job and RBAC resources.
-   `full-deploy` (or no action): Runs `build`, `push`, and `deploy`.

### Command Line Options

The scanner binary accepts the following command-line options. These are configured in the `scanner-job.yaml.template` file.

```bash
./tls-scanner [OPTIONS]
```

**Options:**
- `-host <ip>` - Target host/IP to scan (default: 127.0.0.1)
- `-port <port>` - Target port to scan (default: 443)  
- `-all-pods` - Scan all pods in the cluster (requires cluster access)
- `-component-filter <names>` - Filter pods by component name (comma-separated, used with -all-pods)
- `-namespace-filter <names>` - Filter pods by namespace (comma-separated, used with -all-pods)
- `-json-file <file>` - Output results in JSON format to specified file
- `-csv-file <file>` - Output results in CSV format to specified file
- `-junit-file <file>` - Output results in JUnit XML format to specified file
- `-log-file <file>` - Redirect all log output to the specified file.
- `-j <num>` - Number of concurrent workers (default: 1, max recommended: 50)
