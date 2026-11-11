# Production hardening TDD evidence

## Guarantees covered

- Bootstrap credentials come from a secret and are never emitted to logs.
- Invalid and duplicate registrations do not create users.
- Pull-request webhooks fail closed and require a valid signature.
- Public POST endpoints are rate limited without mixing client buckets.
- CSP reports cannot inject log lines or exhaust request memory.
- ZIP extraction rejects excessive output, entries, and compression ratios.
- Metrics projections are idempotent and preserve failure records after rollback.
- SQS work extends message visibility while a scan is running.
- Production defaults disable registration and the H2 console.

## RED evidence

- The initial focused test compile failed because the new bootstrap-secret constructor and bounded ZIP extraction API did not exist yet.
- The first metrics failure-path test exposed that recording a failure inside the rolled-back transaction lost the failure marker.
- Security, rate-limit, CSP, webhook, ZIP, metrics, SQS, and registration regression tests were added with the implementation work.

## GREEN evidence

- Focused core hardening suite: 69 tests passed.
- Registration controller suite: 5 tests passed.
- Upload REST controller suite: 4 tests passed.
- Complete 12-module Maven reactor: `BUILD SUCCESS`.
- Core module: 993 tests passed.
- JaCoCo core coverage: 87.26% instructions, 76.29% branches, 89.93% lines.
- JaCoCo enforces an 80% instruction-coverage floor.
- Dockerfile static build check completed without warnings.
- The complete image built as `watchtower:hardening-check`; its smoke test ran as UID/GID 1000 with Java 21.0.12, Node 22.23.2, and Checkov 3.3.8.
- Kubernetes and Spring YAML files parse successfully.
- `git diff --check` passes after final whitespace cleanup.

## Rollout checks

- Populate the Kubernetes bootstrap-admin password secret before deployment.
- Configure the Bitbucket webhook secret at both ends before deploying the fail-closed webhook behavior.
- Check production data for duplicate usernames before Flyway applies `V041`.
