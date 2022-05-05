package com.tracelink.appsec.watchtower.core.scan.image.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.tracelink.appsec.watchtower.core.scan.image.entity.AdvisoryEntity;

/**
 * Repository definition for an Advisory
 * 
 * @author csmith
 *
 */
@Repository("advisoryRepository")
public interface AdvisoryRepository extends JpaRepository<AdvisoryEntity, Long> {

	/**
	 * Given an advisory name return the advisory, or null
	 * 
	 * @param advisoryName the name of an advisory (e.g. CVE-XXXX-XXXX)
	 * @return the advisory entity for this name, or null if none found
	 */
	AdvisoryEntity findByAdvisoryName(String advisoryName);

}
