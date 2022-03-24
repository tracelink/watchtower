package com.tracelink.appsec.watchtower.core.scan.code.pr.repository;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import com.tracelink.appsec.watchtower.core.scan.IViolationRepository;
import com.tracelink.appsec.watchtower.core.scan.code.pr.entity.PullRequestScanEntity;
import com.tracelink.appsec.watchtower.core.scan.code.pr.entity.PullRequestViolationEntity;

/**
 * Violation Repository for Pull Requests
 * 
 * @author csmith
 *
 */
@Repository("prViolationRepository")
public interface PRViolationRepository extends IViolationRepository<PullRequestViolationEntity> {

	@Query("SELECT v.scan FROM PullRequestViolationEntity v GROUP BY v.scan")
	Page<PullRequestScanEntity> findAllGroupByScan(Pageable page);
}
