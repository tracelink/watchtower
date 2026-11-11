/*
 * ShedLock: a scheduled job takes a named lock here so it runs on exactly one pod when
 * Watchtower runs more than one. One row per job name; rows are reused, never piled up.
 */
CREATE TABLE shedlock (
	name VARCHAR(64) NOT NULL,
	lock_until TIMESTAMP(3) NOT NULL,
	locked_at TIMESTAMP(3) NOT NULL,
	locked_by VARCHAR(255) NOT NULL,
	PRIMARY KEY (name)
);
