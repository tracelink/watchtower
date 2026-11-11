# Java regular-expression rules

Playbook r1-v1. Use the actual scan engine/version when available; managed rule revision alone does not establish engine provenance.

Rules select file extensions and exact Java regex patterns; scanning matches text, not program semantics.

Illustrative examples (not executed): A pattern for an unsafe API may match the literal call in a selected source file. A safe API or different extension is an illustrative negative.

Limitations: Comments, strings, aliases and multiline formatting cause false matches or misses. Backtracking can be expensive. Runtime/configuration affect behavior.

Testing: Use the Regex designer with both matching and clean strings. Escape syntax for Java regex rather than another regex dialect.

Health evidence uses saved rule/revision/window counts and confirmed human feedback. Zero matches do not establish a dead rule. Never treat a PR bypass as correctness ground truth. R1 tools only read evidence.
