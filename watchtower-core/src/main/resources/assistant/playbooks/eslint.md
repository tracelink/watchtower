# ESLint JavaScript rules

Playbook r1-v1. Use the actual scan engine/version when available; managed rule revision alone does not establish engine provenance.

Provided rules select built-in catalog keys. Custom rules define create(context), schema and message keys. The bridge uses ECMAScript 2020 and an explicit rule map.

Illustrative examples (not executed): A call to eval(userInput) illustrates a dangerous API. A string containing eval is a negative example for an AST call rule.

Limitations: The bridge does not load repository config/plugins. Arbitrary custom JavaScript dependencies retain unknown provenance. Rule messages must reference registered message keys.

Testing: Use the existing ESLint designer with parseable JavaScript, then test computed members, aliases and syntax errors. No assistant test tool is available.

Health evidence uses saved rule/revision/window counts and confirmed human feedback. Zero matches do not establish a dead rule. Never treat a PR bypass as correctness ground truth. R1 tools only read evidence.
