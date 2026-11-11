# PMD Java and supported language rules

Playbook r1-v1. Use the actual scan engine/version when available; managed rule revision alone does not establish engine provenance.

Provided rules select a catalog rule. Custom rules use a supported rule class and properties, often XPath over the engine AST.

Illustrative examples (not executed): A Java Runtime.exec call can illustrate an unsafe command-execution API match. A harmless string containing Runtime.exec should not match an AST rule.

Limitations: Language/parser versions, XPath AST differences, unresolved types and reflection affect results. Function-dependent XPath provenance may be unknown.

Testing: Use the existing PMD designer and version-matched AST viewer; check properties, positive/negative cases and parser failures.

Health evidence uses saved rule/revision/window counts and confirmed human feedback. Zero matches do not establish a dead rule. Never treat a PR bypass as correctness ground truth. R1 tools only read evidence.
