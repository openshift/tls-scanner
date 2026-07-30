// Package testutil provides shared test helpers for the tls-scanner module.
package testutil

import (
	"os"
	"path/filepath"
	"testing"
)

// MockTestSSLScript is a minimal bash script that mimics testssl.sh output.
// It reads a targets file and writes a JSON array of findings.
// Set MOCK_NO_MLKEM=1 in the environment to suppress ML-KEM findings,
// simulating a host that does not support post-quantum key exchange.
//
// Each line of the targets file is normally a bare "host:port" target, but
// may instead start with "--ip=<ip> " followed by "hostname:port" (see
// scanner.targetLine), mirroring how testssl.sh lets a caller connect to an
// explicit IP while sending a different TLS SNI servername. Real testssl.sh
// reports such targets as "ip": "<connect-ip>/<node>" in its JSON output; the
// mock reproduces that so tests can verify results are still attributed to
// the connect IP (see scanner.GroupTestSSLOutputByIPPort, which keys results
// on the ip portion before the "/").
const MockTestSSLScript = `#!/bin/bash
JSONFILE=""
TARGETS_FILE=""
STARTTLS=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --jsonfile) JSONFILE="$2"; shift 2;;
        --file) TARGETS_FILE="$2"; shift 2;;
        --starttls) STARTTLS="$2"; shift 2;;
        *) shift;;
    esac
done
SERVICE="https"
[ -n "$STARTTLS" ] && SERVICE="$STARTTLS"
{
printf '['
FIRST=true
while IFS= read -r target; do
    ip=""
    node_port="$target"
    if [[ "$target" == --ip=* ]]; then
        ip="${target%% *}"
        ip="${ip#--ip=}"
        node_port="${target#* }"
    fi
    node="${node_port%%:*}"
    port="${node_port##*:}"
    [ -z "$ip" ] && ip="$node"
    [ "$FIRST" = true ] && FIRST=false || printf ','
    printf '{"id":"TLS1_2","ip":"%s/%s","port":"%s","severity":"OK","finding":"offered (OK)","service":"%s"},' "$ip" "$node" "$port" "$SERVICE"
    printf '{"id":"TLS1_3","ip":"%s/%s","port":"%s","severity":"OK","finding":"offered (OK)","service":"%s"},' "$ip" "$node" "$port" "$SERVICE"
    printf '{"id":"FS","ip":"%s/%s","port":"%s","severity":"OK","finding":"offered (OK)","service":"%s"}' "$ip" "$node" "$port" "$SERVICE"
    if [ -z "${MOCK_NO_MLKEM:-}" ]; then
        printf ',{"id":"FS_KEMs","ip":"%s/%s","port":"%s","severity":"OK","finding":"x25519mlkem768","service":"%s"}' "$ip" "$node" "$port" "$SERVICE"
    fi
done < "$TARGETS_FILE"
printf ']'
} > "$JSONFILE"
`

// InstallMockTestSSL writes MockTestSSLScript to a temporary directory and
// prepends that directory to PATH, so that calls to "testssl.sh" during the
// test use the mock instead of any real installation. The original PATH is
// restored automatically when the test completes.
func InstallMockTestSSL(t testing.TB) {
	t.Helper()
	mockDir := t.TempDir()
	mockPath := filepath.Join(mockDir, "testssl.sh")
	if err := os.WriteFile(mockPath, []byte(MockTestSSLScript), 0755); err != nil {
		t.Fatalf("failed to write mock testssl.sh: %v", err)
	}
	t.Setenv("PATH", mockDir+":"+os.Getenv("PATH"))
}
