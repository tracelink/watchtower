package com.tracelink.appsec.watchtower.core.scan.code.pr.repository;

import org.springframework.stereotype.Repository;

import com.tracelink.appsec.watchtower.core.scan.IScanRepository;
import com.tracelink.appsec.watchtower.core.scan.code.pr.entity.PullRequestScanEntity;

/**
 * Scan Repository for Pull Requests
 * 
 * @author csmith
 *
 */
@Repository("prScanRepository")
public interface PRScanRepository extends IScanRepository<PullRequestScanEntity> {

}
