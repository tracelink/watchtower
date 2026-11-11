# Container advisory exceptions

Playbook r1-v1. Use the actual scan engine/version when available; managed rule revision alone does not establish engine provenance.

Advisory rules match vulnerability/finding names as image-scan exceptions, not code AST rules.

Illustrative examples (not executed): A matching synthetic vulnerability identifier illustrates an exception match. A different identifier is a negative example.

Limitations: Unmatched image vulnerabilities have no managed exception-rule identity. Advisory exception counts cannot be treated as code-rule opportunities or precision.

Testing: Inspect the exception matcher, scope and lifecycle against controlled image findings. Do not infer exploitability or correctness solely from suppression.

Health evidence uses saved rule/revision/window counts and confirmed human feedback. Zero matches do not establish a dead rule. Never treat a PR bypass as correctness ground truth. R1 tools only read evidence.
