# JSONPath configuration rules

Playbook r2-v1. Use the actual scan engine/version when available; managed rule revision alone does not establish engine provenance.

Rules select file extensions and a JSONPath query with the deployed JSONPath/Jackson semantics.

Illustrative examples (not executed): A query selecting public=true illustrates unsafe configuration. A document with public=false is an illustrative negative.

YAML: .yaml/.yml files use pinned SnakeYAML 2.6 events converted to occurrence-specific JSON nodes. Each document is queried separately and messages identify its document number. Alias/merged values report the alias-use line; explicit overrides report their own line. Merge sequences prefer earlier mappings, and explicit keys override merges regardless of ordering.

Limits: 2 MiB input, 100 documents, 64 levels, 50 aliases and 100,000 expanded nodes. Recursive/forward aliases, duplicate keys/anchors, complex keys, nonfinite numbers, binary/object/custom tags are rejected. Standard scalar/sequence/mapping tags are accepted. YAML 1.1 scalar resolution applies (including yes/no/on/off and legacy numeric forms); timestamps remain strings. Quoted scalars remain strings.

Limitations: location parsing and query results must agree. Equal values keep distinct occurrences. Absent keys and arrays need explicit cases. Computed JSONPath results without source-node identity can have an unknown location.

Testing: Select JSON or YAML in the JSONPath designer. Exercise nested objects, arrays, absent keys, equal values, Kubernetes multi-document files, aliases/merges, overrides and malformed/oversized inputs. Verify locations and document numbers as well as match counts. Assistant examples remain illustrative; only explicit human designer runs execute queries.

Health evidence uses saved rule/revision/window counts and confirmed human feedback. Zero matches do not establish a dead rule. Never treat a PR bypass as correctness ground truth. R1 tools only read evidence.
