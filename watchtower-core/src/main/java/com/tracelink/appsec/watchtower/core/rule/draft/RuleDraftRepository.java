package com.tracelink.appsec.watchtower.core.rule.draft;

import org.springframework.data.jpa.repository.JpaRepository;

public interface RuleDraftRepository extends JpaRepository<RuleDraftEntity, String> {
	/** How many drafts a person still has open (not used, discarded or expired). */
	long countByCreatedByAndStatusAndExpiresAtGreaterThan(String createdBy, String status, long now);

	/** Removes drafts that expired before {@code now}. */
	long deleteByExpiresAtLessThan(long now);
}
