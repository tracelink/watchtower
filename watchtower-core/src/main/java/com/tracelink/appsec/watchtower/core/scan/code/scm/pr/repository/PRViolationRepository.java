package com.tracelink.appsec.watchtower.core.scan.code.scm.pr.repository;

import java.util.Collection;
import java.util.List;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import com.tracelink.appsec.watchtower.core.scan.IViolationRepository;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.entity.PullRequestScanEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.entity.PullRequestViolationEntity;

/**
 * Violation Repository for Pull Requests
 *
 * @author csmith
 *
 */
@Repository("prViolationRepository")
public interface PRViolationRepository extends IViolationRepository<PullRequestViolationEntity> {
	/** One grouped read for a bounded page of PR rows, excluding separately reported MCR matches. */
	@Query("SELECT v.scan.id, v.severity, COUNT(v) FROM PullRequestViolationEntity v "
			+ "WHERE v.scan.id IN :scanIds AND v.violationName NOT LIKE 'MCR Match:%' "
			+ "GROUP BY v.scan.id, v.severity")
	List<Object[]> countSeveritiesByScanId(Collection<Long> scanIds);

	@Query("SELECT v.scan.id, COUNT(v) FROM PullRequestViolationEntity v "
			+ "WHERE v.scan.id IN :scanIds AND v.violationName LIKE 'MCR Match:%' "
			+ "GROUP BY v.scan.id")
	List<Object[]> countMcrByScanId(Collection<Long> scanIds);

	@Query(value = "SELECT v.scan FROM PullRequestViolationEntity v WHERE v.violationName NOT LIKE 'MCR Match:%' GROUP BY v.scan",
			countQuery = "SELECT COUNT(DISTINCT v.scan) FROM PullRequestViolationEntity v WHERE v.violationName NOT LIKE 'MCR Match:%'")
	Page<PullRequestScanEntity> findAllNonMCRGroupByScan(Pageable page);

	/**
	 * @return those of the scans with a finding an earlier bypass covered when it was found
	 */
	@Query("SELECT DISTINCT v.scan.id FROM PullRequestViolationEntity v "
			+ "WHERE v.scan.id IN ?1 AND v.bypassed = true")
	List<Long> findScanIdsWithBypassedFindings(Collection<Long> scanIds);
}
