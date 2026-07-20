# Konflux onboarding and reusable TLS scan pipeline

This directory holds Konflux resources for:

1. **Onboarding `tls-scanner` itself** so Konflux builds the image and can run
   integration checks on PRs to this repo.
2. **Publishing a reusable compliance-scan Pipeline** that layered products can
   point at from their own `IntegrationTestScenario` (via Tekton git resolver)
   to scan their ephemeral test environments.

## Important: what is and is not auto-applied from git

**None of the `Application` / `Component` / `IntegrationTestScenario` CRs are
watched or auto-applied by Konflux.** Someone with `oc`/`kubectl` access to the
Konflux tenant namespace must apply them explicitly.

Only Pipeline / PipelineRun YAML referenced by an already-applied ITS
`resolverRef` (or by Pipelines-as-Code `.tekton/*.yaml` files) is fetched from
git at run time.

## Layout

| File | Applied to cluster? | Purpose |
|---|---|---|
| [`application.yaml`](application.yaml) | Yes | Konflux `Application` for this component. |
| [`component.yaml`](component.yaml) | Yes | `Component` + `ImageRepository`. Triggers Konflux's PaC bot to open a *separate* onboarding PR with generated `.tekton/` build PipelineRuns — do not hand-write those. Uses `Dockerfile.local` (public bases) so Konflux can build without `registry.ci.openshift.org`. |
| [`integration-test-scenario.yaml`](integration-test-scenario.yaml) | Yes | ITS CRs for this repo's own self-test and smoke checks. |
| [`pipelines/tls-scanner-smoke-test.yaml`](pipelines/tls-scanner-smoke-test.yaml) | No (git-resolved) | Light check: `tls-scanner --version` / `--help` on the Snapshot image. |
| [`pipelines/tls-scanner-self-test.yaml`](pipelines/tls-scanner-self-test.yaml) | No (git-resolved) | End-to-end self-test: smoke + TLS fixture pod + Job-based scan in the PipelineRun namespace. |
| [`pipelines/tls-scanner-compliance-scan.yaml`](pipelines/tls-scanner-compliance-scan.yaml) | No (git-resolved) | **Reusable pipeline for layered products.** Deploys the scanner Job into a target cluster identified by a kubeconfig Secret. |

## Prerequisites

Replace every `<TENANT_NAMESPACE>` placeholder with your Konflux workspace
tenant namespace (commonly `<workspace-name>-tenant`).

Also required:

- Konflux GitHub App installed on the `openshift` org (or at least this repo).
- Push access for branches matching `konflux-*` (PaC onboarding / MintMaker).

## Onboarding tls-scanner (apply order)

1. Fill in `<TENANT_NAMESPACE>` in `application.yaml`, `component.yaml`, and
   `integration-test-scenario.yaml`.
2. `oc apply -f konflux/application.yaml`
3. `oc apply -f konflux/component.yaml` — Konflux opens a separate PaC PR with
   generated `.tekton/*.yaml` build pipelines. Review and merge **that** PR
   before expecting builds.
4. After a build Snapshot exists: `oc apply -f konflux/integration-test-scenario.yaml`

### Validating pipelines from a feature PR

1. Temporarily set each ITS `resolverRef` `revision` param to your branch name
   (e.g. `feat/konflux-tls-scan`).
2. Re-apply the ITS: `oc apply -f konflux/integration-test-scenario.yaml`
3. Open/update the GitHub PR — Konflux posts integration checks (e.g.
   `tls-scanner-self-test`). Click **Details** to open the Tekton UI.
4. Because the ITS carries `test.appstudio.openshift.io/optional: "true"`, a
   failing check will not block the Snapshot while bootstrapping.
5. Flip `revision` back to `main`, re-apply, and merge the PR.

## Using tls-scanner from a layered product

tls-scanner must run **inside** the cluster it scans (it execs into pods and
opens TCP connections to pod IPs). Layered products that already provision an
ephemeral test environment for their Snapshot should:

1. Store a kubeconfig for that environment in a Secret in their Konflux tenant
   namespace (key defaults to `kubeconfig`).
2. Apply an `IntegrationTestScenario` in **their** tenant that points at this
   repo's compliance pipeline:

```yaml
apiVersion: appstudio.redhat.com/v1beta2
kind: IntegrationTestScenario
metadata:
  name: tls-compliance-scan
  namespace: <YOUR_TENANT_NAMESPACE>
  labels:
    # Start optional; flip to "false" once the product is green.
    test.appstudio.openshift.io/optional: "true"
spec:
  application: <YOUR_APPLICATION_NAME>
  contexts:
    - description: TLS compliance scan of the ephemeral test environment
      name: application
  resolverRef:
    resolver: git
    params:
      - name: url
        value: https://github.com/openshift/tls-scanner.git
      # Pin to a tag or known-good commit — avoid tracking main unless intentional.
      - name: revision
        value: main
      - name: pathInRepo
        value: konflux/pipelines/tls-scanner-compliance-scan.yaml
  params:
    - name: TARGET_KUBECONFIG_SECRET
      value: <secret-name-holding-target-kubeconfig>
    # Optional overrides:
    # - name: TARGET_KUBECONFIG_SECRET_KEY
    #   value: kubeconfig
    # - name: SCANNER_IMAGE
    #   value: quay.io/<org>/tls-scanner:<released-tag>
    # - name: NAMESPACE_FILTER
    #   value: my-product-ns
    # - name: PQC_CHECK
    #   value: "true"
    # - name: TLS_PROFILE_TYPE
    #   value: Modern
    # - name: SCAN_NAMESPACE
    #   value: tls-scanner
    # - name: LIMIT_IPS
    #   value: "0"
```

### Compliance pipeline parameters

| Param | Required | Default | Meaning |
|---|---|---|---|
| `SNAPSHOT` | injected | — | Konflux Snapshot JSON. |
| `TARGET_KUBECONFIG_SECRET` | yes | — | Secret name in the PipelineRun namespace with the target cluster kubeconfig. |
| `TARGET_KUBECONFIG_SECRET_KEY` | no | `kubeconfig` | Key inside that Secret. |
| `SCANNER_IMAGE` | no | from Snapshot `tls-scanner` component | Override to pin a released scanner image. |
| `COMPONENT_NAME` | no | `tls-scanner` | Snapshot component name used when `SCANNER_IMAGE` is empty. |
| `SCAN_NAMESPACE` | no | `tls-scanner` | Namespace on the **target** cluster where the Job is created. |
| `NAMESPACE_FILTER` | no | `""` (all pods) | Comma-separated namespaces to scan. |
| `PQC_CHECK` | no | `"false"` | Pass `--pqc-check` when `"true"`. |
| `TLS_PROFILE_TYPE` | no | `""` | Pass `--tls-profile-type` (Old/Intermediate/Modern). |
| `LIMIT_IPS` | no | `"0"` | Cap IPs scanned (`0` = unlimited). |
| `SCANNER_PARALLEL` | no | `"4"` | Job `-j` concurrency. |
| `JOB_TIMEOUT_SECONDS` | no | `"3600"` | Wait budget for the Job. |

The pipeline grants `cluster-reader`, `privileged` SCC, and a small
`tls-scanner-cross-namespace` ClusterRole (pods/exec + ingress/kubelet config
reads) to a ServiceAccount in `SCAN_NAMESPACE`, deploys the Job, waits for
`Scanner finished with exit code:`, copies `results.json` / `results.csv` /
`results.xml` / `scan.log`, then cleans up. It writes Tekton result
`TEST_OUTPUT` as:

```json
{"result":"SUCCESS|FAILURE|ERROR|WARNING","timestamp":"...","note":"...","failures":0,"successes":1,"warnings":0}
```

That is the format the Integration Service uses for GitHub PR checks.

### Target cluster privileges

The kubeconfig in `TARGET_KUBECONFIG_SECRET` must be able to:

- create namespaces / ServiceAccounts / Jobs in `SCAN_NAMESPACE`
- create ClusterRole / ClusterRoleBinding (or have them pre-created)
- `oc adm policy add-cluster-role-to-user` / `add-scc-to-user`
- `oc cp` from the scanner pod

If your ephemeral env provisioning already creates a restricted SA, pre-create
the RBAC and tighten the pipeline later.

## Standardized test result

Integration Service recognizes the Tekton result named **`TEST_OUTPUT`** only.
Custom result names (e.g. a plain `PASSED` string) will not appear as PR checks.

## Relationship to openshift/release CI

Prow jobs in `openshift/release` continue to run unit tests, image builds, and
periodic full-cluster scans for core OpenShift. This Konflux packaging is for
**layered-product Konflux workflows** and for building/testing the scanner image
itself under Konflux — it does not replace the existing Prow periodics.

## Phase notes

- **Phase 1 (this directory):** onboard build + smoke/self-test + reusable
  compliance pipeline for consumers that already have a kubeconfig Secret.
- **Later:** optional second ITS for scanning core OCP components under Konflux;
  tighten RBAC; pin consumer `revision` values to released tags.
