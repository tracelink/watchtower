package com.tracelink.appsec.watchtower.core.scan.code.scm.pr.repository;

import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.PullRequestMCRStatus;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.entity.PullRequestContainerEntity;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import com.tracelink.appsec.watchtower.core.scan.IScanRepository;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.entity.PullRequestScanEntity;

import java.util.List;

/**
 * Scan Repository for Pull Requests
 * 
 * @author csmith
 *
 */
@Repository("prScanRepository")
public interface PRScanRepository extends IScanRepository<PullRequestScanEntity> {

    @Query(value = "SELECT p FROM PullRequestScanEntity AS p WHERE p.mcrStatus = ?1 AND EXISTS(SELECT 1 FROM PullRequestScanEntity AS p2 WHERE p2.container = p.container GROUP BY p2.container HAVING p.submitDate = MAX(p2.submitDate))",
            countQuery = "SELECT COUNT(p3) FROM PullRequestScanEntity p3 WHERE EXISTS(SELECT p FROM PullRequestScanEntity AS p WHERE p.mcrStatus = ?1 AND EXISTS(SELECT 1 FROM PullRequestScanEntity AS p2 WHERE p2.container = p.container GROUP BY p2.container HAVING p.submitDate = MAX(p2.submitDate)))")
    Page<PullRequestScanEntity> findLatestMcrsPerPRByMcrStatus(PullRequestMCRStatus mcrStatus, Pageable pageable);

    @Query(value = "SELECT p FROM PullRequestScanEntity AS p WHERE p.mcrStatus <> ?1 AND p.mcrStatus IS NOT NULL AND EXISTS(SELECT 1 FROM PullRequestScanEntity AS p2 WHERE p2.container = p.container GROUP BY p2.container HAVING p.submitDate = MAX(p2.submitDate))",
            countQuery = "SELECT COUNT(p3) FROM PullRequestScanEntity p3 WHERE EXISTS(SELECT p FROM PullRequestScanEntity AS p WHERE p.mcrStatus <> ?1 AND p.mcrStatus IS NOT NULL AND EXISTS(SELECT 1 FROM PullRequestScanEntity AS p2 WHERE p2.container = p.container GROUP BY p2.container HAVING p.submitDate = MAX(p2.submitDate)))")
    Page<PullRequestScanEntity> findLatestMcrsPerPR(PullRequestMCRStatus mcrStatus, Pageable pageable);

}
