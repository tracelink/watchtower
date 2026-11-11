-- Existing rows serialize ORM creation/aggregation where a unique ledger row does not yet exist.
CREATE TABLE application_persistence_locks (
 lock_name VARCHAR(64) NOT NULL PRIMARY KEY
);
INSERT INTO application_persistence_locks VALUES ('rule-metrics'), ('metrics-projections'), ('rule-health');
