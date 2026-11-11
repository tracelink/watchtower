# Reviewed rule-test fixtures

Small, secret-free, UTF-8 files (each under 64 KB) that Watchtower runs a rule candidate against.
Dev only: the image carries them to /opt/watchtower/rule-fixtures and deploy.sh points
`watchtower.rule-testing.fixture-directory` at that path for Dev. Prod does not set it.

A fixture's SHA-256 is registered with the rule; changing a file here invalidates the evidence.

| Reference | Cohort | Expected for the narrowed `debugDump\(request` candidate |
|---|---|---|
| regression/match.java | REGRESSION | MATCH |
| regression/no-match.java | REGRESSION | NO_MATCH |
| holdout/match.java | HOLDOUT | MATCH |
| holdout/no-match.java | HOLDOUT | NO_MATCH (the broad rule matches it, the candidate does not) |
