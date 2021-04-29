package com.tracelink.appsec.watchtower.core.scan.upload.repository;

import org.springframework.stereotype.Repository;

import com.tracelink.appsec.watchtower.core.scan.IScanRepository;
import com.tracelink.appsec.watchtower.core.scan.upload.entity.UploadScanEntity;

/**
 * Scan Repository for Pull Requests
 * 
 * @author csmith
 *
 */
@Repository("uploadScanRepository")
public interface UploadScanRepository extends IScanRepository<UploadScanEntity> {

}
