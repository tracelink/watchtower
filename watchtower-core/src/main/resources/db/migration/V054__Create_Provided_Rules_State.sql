-- What each module's provided rules looked like when they were last imported, so startup can
-- skip modules whose provided rules did not change (it used to rewrite every provided rule on
-- every boot, which took most of the startup time).
--   module_name: the module, e.g. Betterleaks
--   fingerprint: SHA-256 hex of the provided rulesets and rules (ProvidedRulesFingerprint)
--   imported_at: epoch millis of that import
-- module_name is VARCHAR(255): 1020 bytes in utf8mb4, under InnoDB's 3072-byte key cap.
CREATE TABLE provided_rules_state (
  module_name VARCHAR(255) NOT NULL,
  fingerprint CHAR(64) NOT NULL,
  imported_at BIGINT NOT NULL,
  PRIMARY KEY (module_name)
);
