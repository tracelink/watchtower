package com.tracelink.appsec.watchtower.core.scan.image.repository;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
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

	/** The few columns needed to filter, sort and page advisories; descriptions stay unread. */
	interface AdvisorySummary {
		long getId();

		String getAdvisoryName();

		String getScore();
	}

	/**
	 * Advisories whose identifier or package matches an escaped LIKE pattern. Descriptions are
	 * stored hex-encoded, so the database cannot search them.
	 */
	@Query("SELECT a.id AS id, a.advisoryName AS advisoryName, a.score AS score FROM AdvisoryEntity a"
			+ " WHERE LOWER(a.advisoryName) LIKE :pattern ESCAPE '!' OR LOWER(COALESCE(a.packageName,'')) LIKE :pattern ESCAPE '!'")
	List<AdvisorySummary> searchSummaries(@Param("pattern") String pattern);

}
