package com.tracelink.appsec.watchtower.core.scan.code.upload.repository;

import org.springframework.stereotype.Repository;

import com.tracelink.appsec.watchtower.core.scan.code.IContainerRepository;
import com.tracelink.appsec.watchtower.core.scan.code.upload.entity.UploadScanContainerEntity;

/**
 * Container Repository for Pull Requests
 * 
 * @author csmith
 *
 */
@Repository("uploadContainerRepository")
public interface UploadContainerRepository extends IContainerRepository<UploadScanContainerEntity> {
	UploadScanContainerEntity findByTicket(String ticket);
}
