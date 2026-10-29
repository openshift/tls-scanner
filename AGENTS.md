# AGENTS.md

## What this project is

TLS compliance scanner for OpenShift/Kubernetes clusters. Runs as an in-cluster Job, discovers pods and their listening TCP ports, then uses testssl.sh to enumerate TLS versions, cipher suites, and key exchange groups. Includes post-quantum (ML-KEM) readiness checks.

## Project layout

```
cmd/tls-scanner/       Entry point, flag parsing, orchestration
internal/k8s/          Kubernetes client, pod discovery, /proc port discovery, TLS profile extraction
internal/scanner/      testssl.sh integration, result parsing, compliance checks, PQC readiness, policy engine
internal/output/       JSON, CSV, JUnit, dry-run output writers
internal/stringutil/   Small string helpers shared by the scanner
internal/timing/       Scan timing collector
internal/testutil/     Mock testssl.sh for unit tests
internal/testdata/     Test fixtures
hack/                  Developer helper scripts (tls_failure_report.py)
deploy.sh              Build/push/deploy/cleanup driver for in-cluster scans
scanner-job*.template  Job manifests for pod and host (MicroShift) scan modes
```

## Build and test

```bash
make build        # Static binary -> bin/tls-scanner
make test         # Unit tests (skips integration)
make check        # fmt-check + vet + lint + govulncheck + test
make tools        # Install golangci-lint and govulncheck
make coverage     # Test coverage report
```

## Key design decisions

- testssl.sh is the TLS probe engine (not nmap). Runs as a batch `--file` scan with `--parallel`.
- Discovery before scan: ports found from pod spec + `/proc/net/tcp`, then filtered (localhost-only, health probes) before the TLS batch.
- Policy engine (`internal/scanner/policy.go` + `policy.yaml`): maps components to TLS profile expectations (ingress, apiserver, kubelet, default). Embedded at build time.
- Scan statuses: `OK`, `NO_TLS`, `LOCALHOST_ONLY`, `NO_PORTS`, `PROBE_PORT` (see `internal/scanner/types.go`).
- Vendor directory is committed. Run `go mod vendor` after dependency changes.

## CI (openshift/release)

Prow runs presubmits via ci-operator config at `ci-operator/config/openshift/tls-scanner/` in openshift/release. Current checks: `unit` (`make test`), `images`, and optional `smoke-tls`. Periodics (`periodic-default-tls`, `periodic-pqc-readiness`, `periodic-tls13-adherence`) run full cluster scans on AWS; TLS 1.3 adherence also runs on GCP and Azure.

## AI code review (Qodo)

`.pr_agent.toml` configures [Qodo](https://docs.qodo.ai) to run `/agentic_review` automatically when a PR is opened. Reviews appear as a persistent summary comment. Requires a Red Hat Qodo license to trigger. See the [Qodo docs](https://docs.qodo.ai/code-review/get-started/configuration-overview/configuration-file) for config options.

## Conventions

- Go 1.25+, `CGO_ENABLED=0` static builds
- `log/slog` for structured logging (`-log-level` controls verbosity)
- No hardcoded values -- use flags, env vars, or policy.yaml
- Table-driven tests
- Run `make check` before submitting PRs
