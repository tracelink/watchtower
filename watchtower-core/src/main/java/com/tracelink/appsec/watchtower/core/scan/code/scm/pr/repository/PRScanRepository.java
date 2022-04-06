package com.tracelink.appsec.watchtower.core.scan.code.scm.pr.repository;

import org.springframework.stereotype.Repository;

import com.tracelink.appsec.watchtower.core.scan.code.IScanRepository;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.entity.PullRequestScanEntity;

/**
 * Scan Repository for Pull Requests
 * 
 * @author csmith
 *
 */
@Repository("prScanRepository")
public interface PRScanRepository extends IScanRepository<PullRequestScanEntity> {

}
