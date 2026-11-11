# Checkov infrastructure checks

Playbook r1-v1. Use the actual scan engine/version when available; managed rule revision alone does not establish engine provenance.

Provided definitions select Checkov check keys. R1 does not expose arbitrary Python rule authoring.

Illustrative examples (not executed): A public cloud storage resource can illustrate a selected public-access check. A private resource is a negative example; exact behavior depends on the selected check.

Limitations: Python/catalog versions, framework configuration, external modules and integrations affect evaluation. Current execution fingerprints are partial and disable repository reuse.

Testing: Use documented engine/framework settings and controlled Checkov fixtures. ProcessRunner bounds execution; it is not a sandbox. Parsing failures are missing coverage.

Health evidence uses saved rule/revision/window counts and confirmed human feedback. Zero matches do not establish a dead rule. Never treat a PR bypass as correctness ground truth. R1 tools only read evidence.
