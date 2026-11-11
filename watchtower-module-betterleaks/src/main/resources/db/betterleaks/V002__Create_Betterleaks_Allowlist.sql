CREATE TABLE betterleaks_allowlist (
  entry_id BIGINT NOT NULL AUTO_INCREMENT,
  scope VARCHAR(16) NOT NULL,
  repo_name VARCHAR(255) NULL,
  path_glob VARCHAR(300) NULL,
  rule_id VARCHAR(100) NULL,
  reason VARCHAR(500) NOT NULL,
  created_by VARCHAR(255) NOT NULL,
  created_at BIGINT NOT NULL,
  expires_at BIGINT NULL,
  PRIMARY KEY (entry_id)
);
