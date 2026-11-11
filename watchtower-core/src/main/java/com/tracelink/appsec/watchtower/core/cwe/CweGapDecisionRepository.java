package com.tracelink.appsec.watchtower.core.cwe;

import org.springframework.data.jpa.repository.JpaRepository;

public interface CweGapDecisionRepository extends JpaRepository<CweGapDecisionEntity, String> {
	/** Removes every decision about one weakness, for when it leaves the profile. */
	void deleteByCweId(int cweId);
}
