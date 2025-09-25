# tls-scanner

A network security scanner for OpenShift/Kubernetes clusters that combines nmap port scanning with SSL/TLS cipher enumeration and OpenShift component analysis.

## Prerequisites

- **OpenShift/Kubernetes cluster access** - For cluster scanning features
- **Sufficient privileges** - Pod exec and cluster-reader permissions for full functionality

## Installation & Setup

### Local Usage

1. **Build the scanner:**
   ```bash
   go build -o tls-scanner .
   ```

2. **Set up cluster access:**
   ```bash
   export KUBECONFIG=/path/to/your/kubeconfig
   # KUBECONFIG must point to the target OpenShift/Kubernetes cluster you want to scan
   ```

### OpenShift Deployment (Recommended)

For comprehensive cluster scanning, deploy as a privileged pod:

```bash
export KUBECONFIG=/path/to/your/kubeconfig
# Set target project
oc new-project scanner-project  # or oc project <existing-project>

# Deploy scanner pod with all necessary permissions
./deploy.sh
```

The deployment script automatically:
- Creates privileged pod with cluster access
- Grants necessary RBAC permissions (cluster-reader, pod-exec)  
- Builds and deploys scanner image
- Runs CSV+Json scan with 15 concurrent workers

## Usage

### Command Line Options

```bash
./tls-scanner [OPTIONS]
```

**Options:**
- `-host <ip>` - Target host/IP to scan (default: 127.0.0.1)
- `-port <port>` - Target port to scan (default: 443)  
- `-iplist <file>` - File containing list of IPs to scan (one per line)
- `-all-pods` - Scan all pods in the cluster (requires cluster access)
- `-json <file>` - Output results in JSON format to specified file
- `-csv <file>` - Output results in CSV format to specified file
- `-csv-columns <spec>` - Control CSV columns: 'all', 'default', 'minimal', or comma-separated list (default: 'default')
- `-service-mapping <file>` - Generate service-to-IP mapping JSON file (auto-generated for cluster scans)
- `-j <num>` - Number of concurrent workers (default: 1, max recommended: 50)

### Usage Examples

**Scan a single host:**
```bash
./tls-scanner -host 10.0.0.1 -port 443
```

**Scan multiple IPs from file:**
```bash
echo -e "10.0.0.1\n10.0.0.2\n10.0.0.3" > targets.txt
./tls-scanner -iplist targets.txt -j 5
```

**Scan entire OpenShift cluster (JSON output):**
```bash
export KUBECONFIG=/path/to/cluster/config
./tls-scanner -all-pods -json results.json -j 12
```

**CSV security scan with default columns:**
```bash
./tls-scanner -all-pods -csv security-scan-$(date +%Y%m%d).csv -j 15
```

**Full security analysis with all columns:**
```bash  
./tls-scanner -all-pods -csv full-scan-$(date +%Y%m%d).csv -csv-columns all -j 15
```

**Minimal TLS analysis:**
```bash
./tls-scanner -all-pods -csv minimal-$(date +%Y%m%d).csv -csv-columns minimal -j 15
```

**Custom column selection:**
```bash
./tls-scanner -all-pods -csv custom-$(date +%Y%m%d).csv -csv-columns "IP Address,Port,Service,TLS Version,Cipher Suites,Process Name" -j 15
```

**Json+CSV security scan (auto-generates service mapping):**
```bash
./tls-scanner -all-pods -csv security-scan-$(date +%Y%m%d).csv -json security-scan-$(date +%Y%m%d).json -j 15
```

### Required Permissions

The scanner requires these RBAC permissions:

```yaml
# Cluster-wide read access
- pods (get, list)
- pods/exec (create)

# ClusterRoles granted:
- cluster-reader
- pod-exec-reader (custom)

# SecurityContextConstraints:
- privileged (for comprehensive scanning)
```
`./deploy.sh` automatically sets these permissions for you.

## Configuration

### Environment Variables
- `KUBECONFIG` - **Required** - Path to kubeconfig file for target cluster
  
```mermaid
graph LR
    subgraph "Architecture"
        subgraph "Scanning Workflow"
            A[1. IP Discovery] --> B[2. Port Scan]
            B --> C[3. SSL Analysis]
            C --> D[4. Component Analysis]
            D --> E[5. Query Process ID]
            E --> F[6. Aggregate Results]
        end
    end

```
  