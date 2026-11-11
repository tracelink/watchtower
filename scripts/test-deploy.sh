#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
TEST_ROOT=$(mktemp -d)
trap 'rm -rf "$TEST_ROOT"' EXIT

MOCK_BIN="$TEST_ROOT/bin"
mkdir -p "$MOCK_BIN"

cat > "$MOCK_BIN/aws" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [[ "$1 $2" == "sts get-caller-identity" ]]; then
  exit 0
fi
if [[ "$1 $2" == "ecr get-login-password" ]]; then
  printf 'mock-password\n'
  exit 0
fi
if [[ "$1 $2" == "ecr describe-images" ]]; then
  exit 0
fi
if [[ "$1 $2" == "eks update-kubeconfig" ]]; then
  exit 0
fi
echo "unexpected aws invocation: $*" >&2
exit 1
EOF

cat > "$MOCK_BIN/docker" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
case "${1:-} ${2:-}" in
  "login --username") cat >/dev/null; exit 0 ;;
  "image inspect") exit 0 ;;
  "tag watchtower:26.1.1") exit 0 ;;
  "push 444455556666.dkr.ecr.us-east-1.amazonaws.com/watchtower:26.1.1") exit 0 ;;
esac
echo "unexpected docker invocation: $*" >&2
exit 1
EOF

cat > "$MOCK_BIN/kubectl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "$MOCK_KUBECTL_LOG"
if [[ "$1 $2" == "config current-context" ]]; then
  printf 'arn:aws:eks:us-east-1:123456789012:cluster/prod-eks-cluster\n'
  exit 0
fi
if [[ "$1 $2" == "apply -f" ]]; then
  if grep -q '"kind": "Secret"' "$3"; then
    cp "$3" "$MOCK_APPLIED_SECRET"
  fi
  exit 0
fi
if [[ "$1 $2" == "create -f" ]]; then
  if grep -q '"kind": "Secret"' "$3"; then
    cp "$3" "$MOCK_APPLIED_SECRET"
  fi
  exit 0
fi
if [[ "$1 $2 $3" == "get secret watchtower-secrets" ]]; then
  case "${MOCK_SECRET_MODE:-missing}" in
    missing|legacy) exit 1 ;;
    incomplete) printf 'incomplete' ;;
    complete|conflict) printf 'complete' ;;
  esac
  exit 0
fi
if [[ "$1 $2 $3" == "get configmap watchtower-secrets" ]]; then
  if [[ "${MOCK_SECRET_MODE:-missing}" == "legacy" ]]; then
    printf '%s\n' '{"data":{"db_url":"jdbc:legacy-secret-value","db_user":"legacy-secret-user","db_pass":"legacy-secret-password"}}'
    exit 0
  fi
  if [[ "${MOCK_SECRET_MODE:-missing}" == "conflict" ]]; then
    printf '%s\n' '{"data":{"db_url":"must-not-overwrite","db_user":"must-not-overwrite","db_pass":"must-not-overwrite"}}'
    exit 0
  fi
  exit 1
fi
if [[ "$1 $2 $3" == "get ingress watchtower-ingress" && "$*" == *jsonpath* ]]; then
  if [[ "$*" == *certificate-arn* ]]; then
    printf 'arn:aws:acm:us-east-1:123456789012:certificate/mock'
  else
    printf 'sg-0123456789abcdef0'
  fi
  exit 0
fi
if [[ "$1 $2 $3" == "get ingress watchtower-ingress" ]]; then
  printf '%s\n' '{"metadata":{"annotations":{"alb.ingress.kubernetes.io/group.name":"watchtower","alb.ingress.kubernetes.io/tags":"Environment=prod"}}}'
  exit 0
fi
if [[ "$1 $2 $3" == "get deployment watchtower-deployment" ]]; then
  if [[ "${MOCK_SECRET_MODE:-missing}" == "complete" ]]; then
    printf '%s\n' '{"spec":{"replicas":2,"template":{"spec":{"containers":[{"resources":{"requests":{"cpu":"1","memory":"2Gi"},"limits":{"cpu":"2","memory":"4Gi"}},"env":[{"name":"watchtower.allowRegistration","value":"true"},{"name":"watchtower.queue.sqs.visibility-extension-seconds","value":"450"}]}]}}}}'
    exit 0
  fi
  exit 1
fi
echo "unexpected kubectl invocation: $*" >&2
exit 1
EOF

chmod +x "$MOCK_BIN/aws" "$MOCK_BIN/docker" "$MOCK_BIN/kubectl"

run_deploy() {
  local mode=$1
  local output_file=$2
  local bootstrap_password=${3:-}
  local dry_run=${4:-true}
  (
    cd "$REPO_ROOT"
    args=("${DEPLOY_ENV:-prod}" --yes)
    if [[ "$dry_run" == "true" ]]; then
      args+=(--dry-run)
    fi
    PATH="$MOCK_BIN:$PATH" TMPDIR="$TEST_ROOT" MOCK_SECRET_MODE="$mode" \
      MOCK_APPLIED_SECRET="$TEST_ROOT/applied-secret.json" \
      MOCK_KUBECTL_LOG="$TEST_ROOT/kubectl.log" \
      WATCHTOWER_BOOTSTRAP_ADMIN_PASSWORD="$bootstrap_password" \
      ./deploy.sh "${args[@]}"
  ) >"$output_file" 2>&1
}

missing_output="$TEST_ROOT/missing.out"
if run_deploy missing "$missing_output"; then
  echo "FAIL: deployment succeeded without the required Kubernetes Secret" >&2
  exit 1
fi
grep -q "watchtower-secrets" "$missing_output"

legacy_output="$TEST_ROOT/legacy.out"
if ! run_deploy legacy "$legacy_output" "bootstrap-secret-from-environment"; then
  echo "FAIL: deploy.sh did not migrate the legacy ConfigMap into a Secret" >&2
  sed -e 's/legacy-secret-value/[redacted]/g' \
      -e 's/legacy-secret-user/[redacted]/g' \
      -e 's/legacy-secret-password/[redacted]/g' \
      -e 's/bootstrap-secret-from-environment/[redacted]/g' \
      "$legacy_output" >&2
  exit 1
fi
grep -q "Would create Kubernetes Secret 'watchtower-secrets'" "$legacy_output"
for forbidden in legacy-secret-value legacy-secret-user legacy-secret-password bootstrap-secret-from-environment; do
  if grep -q "$forbidden" "$legacy_output"; then
    echo "FAIL: deployment output disclosed migrated secret material" >&2
    exit 1
  fi
done

actual_migration_output="$TEST_ROOT/actual-migration.out"
run_deploy legacy "$actual_migration_output" "bootstrap-secret-from-environment" false
test -f "$TEST_ROOT/applied-secret.json"
python3 - "$TEST_ROOT/applied-secret.json" <<'PYEOF'
import base64
import json
import sys

with open(sys.argv[1]) as stream:
    secret = json.load(stream)

decoded = {key: base64.b64decode(value).decode()
           for key, value in secret["data"].items()}
assert decoded == {
    "db_url": "jdbc:legacy-secret-value",
    "db_user": "legacy-secret-user",
    "db_pass": "legacy-secret-password",
    "bootstrap_admin_password": "bootstrap-secret-from-environment",
}
PYEOF

rm -f "$TEST_ROOT/applied-secret.json"
conflict_output="$TEST_ROOT/conflict.out"
run_deploy conflict "$conflict_output" "" false
if [[ -f "$TEST_ROOT/applied-secret.json" ]]; then
  echo "FAIL: legacy ConfigMap overwrote an already-complete Secret" >&2
  exit 1
fi
grep -q "Reusing existing Kubernetes Secret" "$conflict_output"

legacy_without_bootstrap_output="$TEST_ROOT/legacy-without-bootstrap.out"
if run_deploy legacy "$legacy_without_bootstrap_output"; then
  echo "FAIL: ConfigMap migration succeeded without a bootstrap password" >&2
  exit 1
fi
grep -q "WATCHTOWER_BOOTSTRAP_ADMIN_PASSWORD" "$legacy_without_bootstrap_output"

incomplete_output="$TEST_ROOT/incomplete.out"
if run_deploy incomplete "$incomplete_output"; then
  echo "FAIL: deployment succeeded without bootstrap_admin_password" >&2
  exit 1
fi
grep -q "bootstrap_admin_password" "$incomplete_output"

complete_output="$TEST_ROOT/complete.out"
rm -f "$TEST_ROOT/kubectl.log"
run_deploy complete "$complete_output"

grep -q "Reusing existing Kubernetes Secret; deploy.sh will not apply or modify it" "$complete_output"
if grep -q "get configmap watchtower-secrets" "$TEST_ROOT/kubectl.log"; then
  echo "FAIL: deploy.sh queried bootstrap sources after finding a complete Secret" >&2
  exit 1
fi
if grep -Eq "^(apply|create) -f" "$TEST_ROOT/kubectl.log"; then
  echo "FAIL: deploy.sh reapplied an already-complete Secret" >&2
  exit 1
fi

if grep -q "never-print-this-secret" "$complete_output"; then
  echo "FAIL: deployment output disclosed the bootstrap secret" >&2
  exit 1
fi

rendered_file=$(sed -n 's/^    Rendered manifest kept at: \(.*\) (dry-run skips cleanup)$/\1/p' "$complete_output")
test -n "$rendered_file"

python3 - "$rendered_file" <<'PYEOF'
import sys
import yaml

with open(sys.argv[1]) as stream:
    docs = list(yaml.safe_load_all(stream))

deployment = next(doc for doc in docs if doc.get("kind") == "Deployment")
pod_spec = deployment["spec"]["template"]["spec"]
container = pod_spec["containers"][0]
env = {item["name"]: item for item in container["env"]}

assert pod_spec["securityContext"]["runAsNonRoot"] is True
assert container["securityContext"]["allowPrivilegeEscalation"] is False
assert container["securityContext"]["capabilities"]["drop"] == ["ALL"]
assert env["watchtower.allowRegistration"]["value"] == "false"
assert env["watchtower.queue.sqs.visibility-extension-seconds"]["value"] == "450"
assert env["WATCHTOWER_BOOTSTRAP_ADMIN_PASSWORD"]["valueFrom"]["secretKeyRef"]["name"] == "watchtower-secrets"
assert env["JDBC_URL"]["valueFrom"]["secretKeyRef"]["name"] == "watchtower-secrets"
assert "!!!" not in open(sys.argv[1]).read()
# Dev-only test switches must never reach prod.
assert "WATCHTOWER_RULE_TESTING_FIXTURE_DIRECTORY" not in env
assert "WATCHTOWER_BETTERLEAKS_VERIFICATION_ENABLED" not in env
PYEOF

dev_output="$TEST_ROOT/dev.out"
if ! DEPLOY_ENV=dev run_deploy complete "$dev_output"; then
  echo "FAIL: deploy.sh dev dry-run did not render" >&2
  tail -20 "$dev_output" >&2
  exit 1
fi
dev_rendered=$(sed -n 's/^    Rendered manifest kept at: \(.*\) (dry-run skips cleanup)$/\1/p' "$dev_output")
test -n "$dev_rendered"
python3 - "$dev_rendered" <<'PYEOF'
import sys
import yaml

with open(sys.argv[1]) as stream:
    docs = list(yaml.safe_load_all(stream))
deployment = next(doc for doc in docs if doc.get("kind") == "Deployment")
env = {item["name"]: item["value"] for item in deployment["spec"]["template"]["spec"]["containers"][0]["env"]
       if "value" in item}
names = [item["name"] for item in deployment["spec"]["template"]["spec"]["containers"][0]["env"]]
assert env["WATCHTOWER_RULE_TESTING_FIXTURE_DIRECTORY"] == "/opt/watchtower/rule-fixtures"
assert env["WATCHTOWER_BETTERLEAKS_VERIFICATION_ENABLED"] == "true"
assert len(names) == len(set(names)), "duplicate env var names"
PYEOF

echo "PASS: deploy.sh validates secrets and preserves the hardened manifest"
