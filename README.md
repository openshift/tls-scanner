# tls-scanner

A TLS compliance scanner for OpenShift/Kubernetes clusters. Uses [testssl.sh](https://testssl.sh/) to enumerate TLS versions, cipher suites, key exchange groups, and certificate signature algorithms across cluster pods, with post-quantum (ML-KEM) readiness checks.

## Prerequisites

- **Go environment** - For building the scanner binary.
- **Container tool** - Docker or Podman for building and pushing the scanner image.
- **OpenShift/Kubernetes cluster access** - `oc` or `kubectl` configured to point to your target cluster.
- **Sufficient privileges** - Permissions to create Jobs and RBAC resources. `deploy.sh` grants the `cluster-reader` ClusterRole, a cross-namespace reader ClusterRole, and the `privileged` SCC to the `default` ServiceAccount in the scan namespace.

## Installation & Usage

The scanner is designed to be run from within the cluster it is scanning. This is the most reliable way to ensure network access to all pods. The included `deploy.sh` script automates the build and deployment process.

### CI/CD Workflow (Recommended)

This is the recommended approach for automated scanning in an ephemeral test environment.

#### 1. Configure Environment

Set these environment variables in your CI job:

- `SCANNER_IMAGE`: The full tag of the image to build and push (e.g., `quay.io/my-org/tls-scanner:latest`).
- `NAMESPACE`: The OpenShift/Kubernetes namespace where the scanner Job will be deployed (e.g., `scanner-project`). **Note:** This does NOT restrict what gets scanned - it only determines where the scanner runs.
- `NAMESPACE_FILTER`: (Optional) Comma-separated list of namespaces to scan. If not set, the scanner will scan all pods in the entire cluster. Example: `production,staging` to scan only those namespaces.
- `KUBECONFIG`: Path to the kubeconfig file for the ephemeral test cluster.
- `JOB_TEMPLATE_FILE`: (Optional) Path to the Job manifest template used by `deploy.sh deploy` (default: `scanner-job.yaml.template`). For host-based scanning, use a template that runs with host network access (e.g. `scanner-job-microshift.yaml.template`).
- `SCAN_MODE`: (Optional) `pod` (default) or `host`. **Pod mode** discovers pods in the cluster and scans their TLS ports. **Host mode** is for environments where core components (API server, etcd, kubelet) run on the host rather than in pods—e.g. single-node or edge setups such as MicroShift. Use a job template with `hostNetwork: true` and set `SCAN_MODE=host` so the scanner runs on the host and can reach those services.
- `BUILD_PLATFORMS`: (Optional) Comma-separated platforms for a multi-arch image build. Default: `linux/amd64,linux/arm64,linux/s390x,linux/ppc64le`. When `DOCKERFILE=Dockerfile.local`, `TARGET_PLATFORM` (default `linux/amd64`) is used instead.

See [`deploy.sh` Script Actions](#deploysh-script-actions) for the full list of tuning variables (scan parallelism, resource requests/limits, artifact wait, STARTTLS mapping).

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

Your `./artifacts` directory will now contain `results.json`, `results.csv`, `scan.log`, and `timing.txt`. When the scanner records per-port errors, it also writes `results_errors.csv` alongside `results.csv`.

#### 5. Cleanup

Remove the scanner Job and associated RBAC permissions from the cluster.

```bash
./deploy.sh cleanup
```

### Host-based scanning

In some environments, core cluster components (API server, etcd, kubelet) run on the host instead of as pods. Examples include single-node and edge deployments such as MicroShift. For those setups, use **host** scan mode so the scanner runs with host network access and can discover and scan TLS services bound to the host:

```bash
JOB_TEMPLATE_FILE=scanner-job-microshift.yaml.template SCAN_MODE=host ./deploy.sh deploy
```

Use `JOB_TEMPLATE_FILE` to point at a job template that sets `spec.hostNetwork: true` (and any required security context). The default `scanner-job.yaml.template` is for pod-based scanning only.

## Understanding Scan Results

### CSV Output Columns

The scanner produces a CSV file with one row per scanned port. The schema (39 columns, in order) is:

**Identity and context**

| Column | Description |
| ------ | ----------- |
| `IP` | Pod IP address that was scanned |
| `Port` | TCP port number |
| `Protocol` | Protocol (typically `tcp`) |
| `Service` | Detected service (e.g., `ssl/tls`) |
| `STARTTLS Protocol` | STARTTLS protocol used for the probe (`mysql`, `postgres`, …), empty for direct TLS |
| `Pod Name` | Kubernetes pod name |
| `Namespace` | Kubernetes namespace |
| `Component Name` | OpenShift component name derived from pod labels or image |
| `Component Maintainer` | Maintainer component associated with the image |
| `Process` | Process name listening on the port (from `/proc`) |
| `Listen Address` | Address the port is bound to (e.g., `127.0.0.1`, `*`, `0.0.0.0`) |

**TLS findings**

| Column | Description |
| ------ | ----------- |
| `TLS Ciphers` | Detected TLS cipher suites |
| `TLS Version` | Detected TLS versions (e.g., `TLSv1.2`, `TLSv1.3`) |
| `TLS Supported Groups` | Advertised TLS named groups / curves |
| `Cert Signature Algorithms` | Certificate signature algorithms offered by the server |

**Result**

| Column | Description |
| ------ | ----------- |
| `Status` | Categorized scan result (see below) |
| `Reason` | Detailed explanation of the status |

**Post-quantum readiness**

| Column | Description |
| ------ | ----------- |
| `TLS 1.3 Supported` | Port negotiated TLS 1.3 |
| `ML-KEM Supported` | Port offered an ML-KEM hybrid/accepted KEM (e.g., `x25519mlkem768`) |
| `ML-KEM KEMs` | ML-KEM groups observed |
| `All KEMs` | All key-encapsulation groups observed |
| `TLS 1.3 Offered` | TLS 1.3 was offered (readiness view) |
| `TLS 1.2 Only` | TLS 1.2 was offered but TLS 1.3 was not |
| `PQC Capable` | TLS 1.3 and ML-KEM are both available |
| `Readiness Notes` | Human-readable readiness conclusion |

**TLS profile compliance** (populated when a cluster TLS profile is available or `-tls-profile-type` is set)

| Column group | Columns |
| ------------ | ------- |
| Ingress | `Ingress Configured Profile`, `Ingress Configured MinVersion`, `Ingress MinVersion Compliance`, `Ingress Configured Ciphers`, `Ingress Cipher Compliance` |
| API server | `API Configured Profile`, `API Configured MinVersion`, `API MinVersion Compliance`, `API Configured Ciphers`, `API Cipher Compliance` |
| Kubelet | `Kubelet Configured MinVersion`, `Kubelet MinVersion Compliance`, `Kubelet Configured Ciphers`, `Kubelet Cipher Compliance` |

### Status Categories

The `Status` column categorizes each port. These are the complete set of values the scanner emits today (see `internal/scanner/types.go`):

| Status | Description | Assessed by `-pqc-check`? |
| ------ | ----------- | ------------------------- |
| `OK` | TLS scan successful - cipher and version information available | Yes |
| `NO_TLS` | Port is open but no TLS was detected (plain HTTP/TCP service, or a TLS handshake that the raw probe could not complete) | No |
| `LOCALHOST_ONLY` | Port is bound to a loopback address and is not reachable from the pod IP | No |
| `NO_PORTS` | Pod declares no listening TCP ports in its spec and none were found in `/proc` | No |
| `PROBE_PORT` | Port is a plaintext liveness/readiness/startup probe endpoint; TLS is not expected | No |

**Known limitation:** unreachable ports (connection refused, timeout, NetworkPolicy block) and database ports that require a STARTTLS handshake are currently also reported as `NO_TLS`; they are not distinguished in the output. See [issue #101](https://github.com/openshift/tls-scanner/issues/101).

### Example Output

```csv
IP,Port,Protocol,Service,STARTTLS Protocol,Pod Name,Namespace,...,Status,Reason,Listen Address
10.128.0.15,8443,tcp,ssl/tls,,kube-apiserver-pod,openshift-kube-apiserver,...,OK,TLS scan successful,*
10.0.53.147,9257,tcp,ssl/tls,,controller-manager-pod,openshift-cloud-controller,...,LOCALHOST_ONLY,"Bound to 127.0.0.1, not accessible from pod IP",127.0.0.1
10.0.87.193,3306,tcp,ssl/tls,mysql,db-pod,app-db,...,OK,TLS scan successful,*
10.128.0.20,8080,tcp,N/A,,metrics-pod,openshift-monitoring,...,PROBE_PORT,"Port is used as a plaintext health probe endpoint (HTTP/TCP/gRPC), TLS not expected",*
10.128.0.21,8081,tcp,N/A,,metrics-pod,openshift-monitoring,...,NO_TLS,Port open but no TLS detected,*
```

### Interpreting Results

1. **LOCALHOST_ONLY ports**: These are internal-only ports bound to a loopback address. They're only accessible from within the pod itself and don't pose external TLS compliance concerns. Common for metrics endpoints that are scraped via sidecar containers.

2. **NO_TLS ports**: These ports are open but no TLS was detected. This may be expected (e.g., plaintext metrics) or may indicate a security concern depending on the data transmitted. Note that unreachable ports also currently surface as `NO_TLS` (see the known limitation above), so check `Reason` and the scan log before concluding a port is plaintext.

3. **PROBE_PORT ports**: These ports are matched to a declared plaintext liveness, readiness, or startup probe (HTTP/TCP/gRPC) and are skipped before the TLS scan because TLS is not expected there.

4. **NO_PORTS**: The pod declares no listening TCP ports in its spec and none were found in `/proc/net/tcp`; there is nothing to scan.

`PROBE_PORT` and `NO_PORTS` ports are not assessed by `-pqc-check`; `LOCALHOST_ONLY` and `NO_TLS` are also excluded from that check (see [Status Categories](#status-categories)).

### Manual Usage

You can also run the steps manually.

1.  **Build the image:** `export SCANNER_IMAGE="your-registry/image:tag"` and run `./deploy.sh build`.
2.  **Push the image:** `./deploy.sh push`.
3.  **Deploy the job:** `export NAMESPACE="scanner-project" NAMESPACE_FILTER="production"` and run `./deploy.sh deploy`
4.  **Monitor and retrieve results** as shown in the CI workflow.
5.  **Clean up** with `./deploy.sh cleanup`.

### `deploy.sh` Script Actions

```bash
./deploy.sh [-v|--verbose] [-n|--namespace-filter <namespaces>] [--limit-ips <num>] [action]
```

| Action | Description |
| ------ | ----------- |
| `build` | Builds the `tls-scanner` binary and container image |
| `push` | Pushes the container image to the registry specified by `$SCANNER_IMAGE` |
| `deploy` | Deploys the scanner Kubernetes Job to the cluster specified by `$KUBECONFIG` and `$NAMESPACE` |
| `cleanup` | Removes the scanner Job and RBAC resources |
| `full-deploy` | Runs `build`, `push`, and `deploy` |
| `test-tls-config` | Development check: builds and deploys, temporarily sets a custom API server TLS profile, verifies the scanner detects it, then restores the original profile. Requires `oc` and `jq`. **Mutates cluster configuration** while it runs |
| _(no action)_ | Runs `full-deploy` **and then `cleanup`** |

Script options: `-v`/`--verbose`, `-n`/`--namespace-filter <namespaces>` (equivalent to `NAMESPACE_FILTER`), and `--limit-ips <num>` (equivalent to `LIMIT_IPS`).

Environment variables:

| Variable | Default | Description |
| -------- | ------- | ----------- |
| `SCANNER_IMAGE` | `quay.io/user/tls-scanner:latest` | Image to build, push, and deploy |
| `NAMESPACE` | current `oc` project | Namespace where the scanner Job runs |
| `NAMESPACE_FILTER` | unset (scan all) | Comma-separated namespaces to scan |
| `LIMIT_IPS` | `0` (no limit) | Cap the number of IPs scanned |
| `JOB_TEMPLATE_FILE` | `scanner-job.yaml.template` | Job manifest template used by `deploy` |
| `SCAN_MODE` | `pod` | `pod` or `host`; `host` skips pod-API setup such as pull-secret linking |
| `DOCKERFILE` | `Dockerfile` | Dockerfile to build; use `Dockerfile.local` for a single-arch local build |
| `BUILD_PLATFORMS` | `linux/amd64,linux/arm64,linux/s390x,linux/ppc64le` | Platforms for multi-arch builds |
| `TARGET_PLATFORM` | `linux/amd64` | Platform used when `DOCKERFILE=Dockerfile.local` |
| `STARTTLS_PORTS` | unset | Passed to the scanner as `--starttls-ports` (e.g. `postgres=5432:6432,mysql=3306`) |
| `SCANNER_PARALLEL` | `4` | Passed to the scanner as `-j` |
| `SCANNER_CPU_REQUEST` / `SCANNER_CPU_LIMIT` | `500m` / `4` | Scanner pod CPU request/limit |
| `SCANNER_MEM_REQUEST` / `SCANNER_MEM_LIMIT` | `4Gi` / `4Gi` | Scanner pod memory request/limit |
| `SCANNER_CPU` / `SCANNER_MEM` | unset | Deprecated; sets both request and limit when the specific variables are unset |
| `ARTIFACT_WAIT` | `30` (CI uses `300`) | Seconds the pod stays alive after the scan for artifact collection |
| `TLS_TEST_TIMEOUT` | `600` | Cluster stabilization timeout for `test-tls-config` |

### Command Line Options

The scanner binary accepts the following command-line options. These are configured in the `scanner-job.yaml.template` file.

```bash
./tls-scanner [OPTIONS]
```

**Target selection**

- `-host <ip>` - Target host/IP to scan (default: 127.0.0.1)
- `-port <port>` - Target port to scan (default: 443)
- `-targets <host:port,...>` - Comma-separated list of host:port targets to scan
- `-template <file>` - Path to a YAML file listing targets (`targets:` with `host` and `ports` entries)
- `-generate-template <file>` - Write a commented sample targets YAML to this path and exit
- `-all-pods` - Scan all pods in the cluster (requires cluster access)
- `-component-filter <names>` - Filter pods by component name (comma-separated, used with -all-pods)*
- `-namespace-filter <names>` - Filter pods by namespace (comma-separated, used with -all-pods)
- `-limit-ips <num>` - Cap number of IPs to scan, for testing (0 = no limit)
- `-dry-run` - Discover and print scan targets without scanning

**Output and logging**

- `-artifact-dir <dir>` - Directory for output files (default: /tmp)
- `-json-file <file>` - Output results in JSON format to the specified file (relative paths are placed under `-artifact-dir`)
- `-csv-file <file>` - Output results in CSV format to the specified file (relative paths are placed under `-artifact-dir`)
- `-junit-file <file>` - Output results in JUnit XML format to the specified file (relative paths are placed under `-artifact-dir`)
- `-timing-file <file>` - Write a timing report to the specified file in `-artifact-dir`
- `-log-file <file>` - Redirect all log output to the specified file
- `-log-level <level>` - Log level: `debug`, `info` (default), `warn`, or `error`
- `-version` - Print version and exit

**Compliance checks**

- `-pqc-check` - Check for TLS 1.3 + ML-KEM (post-quantum) support; exits non-zero on failure. Ports with `NO_TLS`, `LOCALHOST_ONLY`, `NO_PORTS`, or `PROBE_PORT` are **not assessed** and cannot fail this check (see [Status Categories](#status-categories))
- `-expected-groups <groups>` - Comma-separated TLS named groups/curves that endpoints must offer (e.g. `X25519MLKEM768,x25519`). Independent of `-pqc-check`; exits non-zero when the assertion fails
- `-expected-groups-mode <mode>` - How `-expected-groups` is evaluated: `contains` (default; every expected group must be observed, extras allowed) or `exact` (observed set must equal the expected set, order ignored)
- `-tls-profile-type <type>` - Expected cluster TLS profile for compliance checks: `Old`, `Intermediate`, or `Modern`. When set, the scanner skips reading the API server/cluster profile

**Scan tuning**

- `-j <num>` - Number of concurrent scans; 0 = runtime.NumCPU() (default: 0)
- `-scan-timeout-per-target <seconds>` - Per-target budget used to compute the batch scan timeout (default: 90)
- `-connect-timeout <seconds>` - testssl.sh/openssl connect timeout (default: 5)
- `-starttls-ports <mapping>` - Enable STARTTLS for specific ports (e.g., `postgres=5432:6432,mysql=3306`). Comma separates protocols, colon separates multiple ports within a protocol. Supported protocols: `ftp`, `smtp`, `lmtp`, `pop3`, `imap`, `xmpp`, `xmpp-server`, `telnet`, `ldap`, `nntp`, `sieve`, `postgres`, `mysql`. **Auto-detection:** When process names are available from `/proc` discovery (e.g., `postgres`, `mysqld`), STARTTLS is used automatically without needing this flag. Explicit `--starttls-ports` mappings take priority over auto-detection.

### JUnit Output

`-junit-file` writes a JUnit XML suite suitable for CI test reporting. Without `-pqc-check`, each endpoint is reported as a TLS profile compliance case; failures are enforced when the cluster's TLS adherence policy enables enforcement. With `-pqc-check`, cases assert TLS 1.3 and ML-KEM support. Non-`OK` ports that cannot be assessed (`NO_TLS`, `LOCALHOST_ONLY`, `NO_PORTS`, `PROBE_PORT`) are emitted as skipped rather than failed. When `-expected-groups` is set, the suite adds a second per-workload test case asserting that advertised TLS groups match the expected set.

### Exit Codes

| Code | Meaning |
| ---- | ------- |
| `0` | Scan completed and all requested compliance checks passed |
| `1` | Scan or output error, or a compliance check (`-pqc-check`, `-expected-groups`, TLS profile compliance) failed |
| `2` | Usage error: invalid flag, log level, timeout, STARTTLS mapping, TLS profile type, or expected-groups mode |

**Note**

`-component-filter` identifies component name according to the following order:
1. pod.labels['app']
2. pod.labels['component']
3. pod.labels['app.kubernetes.io/name']
4. container.Name
5. name determined from container.Image 