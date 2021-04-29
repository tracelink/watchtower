package com.tracelink.appsec.watchtower.core.scan.upload.repository;

import org.springframework.stereotype.Repository;

import com.tracelink.appsec.watchtower.core.scan.IContainerRepository;
import com.tracelink.appsec.watchtower.core.scan.upload.entity.UploadScanContainerEntity;

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
