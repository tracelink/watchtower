# Betterleaks secret detection

Playbook r1-v1. Use the actual scan engine/version when available; managed rule revision alone does not establish engine provenance.

Provided rules select engine keys. Custom rules define regex, secret group, entropy, keywords and optional filters. Use synthetic tokens exclusively.

Illustrative examples (not executed): A deliberately synthetic test token matching a documented prefix is an illustrative positive. An unrelated low-entropy placeholder is a negative only if the actual rule excludes it.

Limitations: Never display discovered secret values. Allowlisting and verification are separate authorized workflows. Scanner runtime/configuration provenance may be unknown.

Testing: Use the existing Betterleaks designer/tester with secret-free synthetic samples and clean variants. Account for entropy thresholds and group selection.

Health evidence uses saved rule/revision/window counts and confirmed human feedback. Zero matches do not establish a dead rule. Never treat a PR bypass as correctness ground truth. R1 tools only read evidence.
