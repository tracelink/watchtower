package com.tracelink.appsec.watchtower.core.scan.code.upload.repository;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import com.tracelink.appsec.watchtower.core.scan.IViolationRepository;
import com.tracelink.appsec.watchtower.core.scan.code.upload.entity.UploadScanEntity;
import com.tracelink.appsec.watchtower.core.scan.code.upload.entity.UploadViolationEntity;

/**
 * Violation Repository for Pull Requests
 * 
 * @author csmith
 *
 */
@Repository("uploadViolationRepository")
public interface UploadViolationRepository extends IViolationRepository<UploadViolationEntity> {
	@Query("SELECT v.scan FROM UploadViolationEntity v GROUP BY v.scan")
	Page<UploadScanEntity> findAllGroupByScan(Pageable page);
}
