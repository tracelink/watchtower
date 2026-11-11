-- One row per pull request violation someone asked to verify live. The row is also the job:
-- PENDING rows are claimed (RUNNING, with a lease) by the verification worker. Holds no secret,
-- no match and no hash of either.
CREATE TABLE betterleaks_verifications (
  verification_id BIGINT NOT NULL AUTO_INCREMENT,
  violation_id BIGINT NOT NULL,
  state VARCHAR(16) NOT NULL,
  attempts INT NOT NULL,
  next_attempt_at BIGINT NOT NULL,
  lease_until BIGINT NULL,
  requested_by VARCHAR(255) NOT NULL,
  requested_at BIGINT NOT NULL,
  verified_at BIGINT NULL,
  notified_at BIGINT NULL,
  last_error VARCHAR(300) NULL,
  PRIMARY KEY (verification_id),
  CONSTRAINT uk_betterleaks_verification_violation UNIQUE (violation_id),
  CONSTRAINT fk_betterleaks_verification_violation FOREIGN KEY (violation_id)
    REFERENCES pull_request_violations (vio_entity_id) ON DELETE CASCADE
);

CREATE INDEX ix_betterleaks_verifications_due ON betterleaks_verifications (state, next_attempt_at);
