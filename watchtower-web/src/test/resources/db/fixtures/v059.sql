-- Source-free legacy metadata. Duplicate rule names intentionally leave provenance ambiguous.
INSERT INTO rules (rule_id, author, name, message, external_url, priority) VALUES
    (9101, 'legacy-owner', 'Legacy shared name', 'Regex message', '', 2),
    (9102, 'legacy-owner', 'Legacy shared name', 'PMD message', '', 3),
    (9103, 'legacy-owner', 'Legacy ESLint rule', 'ESLint message', '', 2),
    (9104, 'legacy-owner', 'Legacy JSON rule', 'JSON message', '', 2),
    (9105, 'legacy-owner', 'Legacy Checkov rule', 'Checkov message', '', 2),
    (9106, 'legacy-owner', 'Legacy Betterleaks rule', 'Betterleaks message', '', 2),
    (9107, 'legacy-owner', 'Legacy advisory rule', 'Advisory message', '', 2);
INSERT INTO regex_rules (rule_id, file_extension, regex_pattern)
    VALUES (9101, '.java', 'legacy-pattern');
INSERT INTO pmd_rules (rule_id, parser_language, rule_class, description)
    VALUES (9102, 'java', 'net.sourceforge.pmd.lang.rule.XPathRule', 'Legacy description');
INSERT INTO pmd_properties (rule_id, property_name, property_value)
    VALUES (9102, 'xpath', '//SyntheticNode');
INSERT INTO eslint_rules (rule_id, core, create_function, rule_schema)
    VALUES (9103, FALSE, 'synthetic-create-function', '[]');
INSERT INTO eslint_messages (rule_id, message_key, message_value)
    VALUES (9103, 'legacy-message', 'Synthetic diagnostic');
INSERT INTO json_rules (rule_id, file_extension, query)
    VALUES (9104, '.json', '$.synthetic');
INSERT INTO checkov_rules (rule_id, core, checkovtype, entity, iac)
    VALUES (9105, TRUE, 'resource', 'synthetic_resource', 'terraform');
INSERT INTO betterleaks_rules (rule_id, provided, betterleaks_id, category, confidence)
    VALUES (9106, TRUE, 'synthetic-detector', 'GENERIC', 'HIGH');
INSERT INTO advisory_rules (rule_id) VALUES (9107);
INSERT INTO rulesets (ruleset_id, name, description, designation, blocking_level)
    VALUES (9201, 'Legacy ruleset', 'Legacy membership', 'PRIMARY', 2);
INSERT INTO rule_ruleset (ruleset_id, rule_id) VALUES (9201, 9101), (9201, 9102);

INSERT INTO pull_request_container
    (container_id, resolved, api_label, author, source_branch, pr_id, repo_name, last_review_date)
    VALUES (9301, FALSE, 'local', 'legacy-user', 'main', '42', 'local/repository', 1700000000000);
INSERT INTO pull_request_scans
    (scan_entity_id, container_id, submit_date, start_date, end_date, status, blocked, mcr_status)
    VALUES (9302, 9301, 1700000000000, 1700000000001, 1700000000002, 'Done', TRUE, NULL);
INSERT INTO pull_request_violations
    (vio_entity_id, scan_entity_id, violation_name, line_number, severity, file_path)
    VALUES (9303, 9302, 'Legacy shared name', 10, 'HIGH', 'Example.java'),
           (9304, 9302, 'Legacy shared name', 20, 'HIGH', 'Example.java');

INSERT INTO upload_container
    (container_id, name, submitter, ticket, ruleset, file_location)
    VALUES (9401, 'Legacy upload', 'legacy-user', 'LOCAL-1', 'Legacy ruleset', 'expired.zip');
INSERT INTO upload_scans (scan_entity_id, container_id, end_date, status)
    VALUES (9402, 9401, 1700000000002, 'Done');
INSERT INTO upload_violations
    (vio_entity_id, scan_entity_id, violation_name, line_number, severity, file_path)
    VALUES (9403, 9402, 'Legacy shared name', 10, 'HIGH', 'Example.java');

INSERT INTO pull_request_bypasses
    (bypass_id, api_label, repo_name, pr_id, scan_id, bypassed_by, reason, created_at)
    VALUES (9501, 'local', 'local/repository', '42', 9302, 'legacy-user', 'legacy rationale', 1700000000003);
INSERT INTO pull_request_bypass_findings (bypass_id, rule_name, file_path)
    VALUES (9501, 'Legacy shared name', 'Example.java');
INSERT INTO pull_request_bypass_requests
    (request_id, api_label, repo_name, pr_id, scan_id, requested_by, reason, created_at,
     status, pending_key, source, requester_scm_id)
    VALUES (9502, 'local', 'local/repository', '42', 9302, 'legacy-commenter',
            'legacy comment rationale', 1700000000003, 'PENDING', REPEAT('a', 64),
            'PR_COMMENT', 'synthetic-scm-id');
INSERT INTO metrics_scan_daily (scan_type, bucket_start, scan_count, violation_count)
    VALUES ('PULL_REQUEST', 1699920000000, 1, 2);
INSERT INTO metrics_violation_daily (scan_type, bucket_start, violation_name, violation_count)
    VALUES ('PULL_REQUEST', 1699920000000, 'Legacy shared name', 2);
INSERT INTO metrics_processed_scan (scan_type, scan_id, metric_kind)
    VALUES ('PULL_REQUEST', 9302, 'VIOLATION');
