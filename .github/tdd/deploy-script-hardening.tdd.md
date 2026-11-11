# Deployment script hardening TDD evidence

## User journey

As an operator, I want `deploy.sh` to validate and preserve the hardened YAML contract so that a deployment cannot start with missing secrets or silently weaken production controls.

## RED

Command: `./scripts/test-deploy.sh`

Result before implementation: `FAIL: deployment succeeded without the required Kubernetes Secret`

ConfigMap migration RED: `FAIL: deploy.sh did not migrate the legacy ConfigMap into a Secret`

Cluster-owned Secret reuse RED: the complete-Secret case failed because the script still queried
the legacy ConfigMap and did not report the no-modification contract.

## GREEN

Command: `./scripts/test-deploy.sh`

Result: `PASS: deploy.sh validates secrets and preserves the hardened manifest`

## Guarantees

| Guarantee | Evidence |
|---|---|
| Missing `watchtower-secrets` stops deployment before image work | Mocked dry-run integration test |
| Missing or empty `bootstrap_admin_password` stops deployment | Mocked dry-run integration test |
| Legacy ConfigMap database values are migrated into a new Secret | Mocked dry-run and mocked apply integration tests |
| `WATCHTOWER_BOOTSTRAP_ADMIN_PASSWORD` is used only to create a missing Secret | Decoded generated-Secret assertion |
| A complete existing Secret bypasses ConfigMap lookup and all Secret create/apply operations | Kubectl invocation-log assertions |
| An incomplete existing Secret fails closed and is never repaired or overwritten | Mocked incomplete-Secret integration test |
| Missing ConfigMap database keys fail closed | Mocked missing-source integration test |
| Secret values are not printed | Sentinel secret absent from captured output |
| Required `secretKeyRef` mappings survive rendering | Parsed rendered YAML assertions |
| Non-root and dropped-capability settings survive rendering | Parsed rendered YAML assertions |
| A live `allowRegistration=true` cannot override the secure `false` default | Mocked live-deployment assertion |
| New SQS visibility settings can still be inherited intentionally | Mocked live-deployment assertion |

Additional checks: `bash -n`, `git diff --check`, and YAML parsing passed. ShellCheck was unavailable locally.

No real AWS, Docker registry, or Kubernetes mutation was performed; all external commands were mocked. The suite covers both `--dry-run` and the normal create/apply branches against those mocks.
