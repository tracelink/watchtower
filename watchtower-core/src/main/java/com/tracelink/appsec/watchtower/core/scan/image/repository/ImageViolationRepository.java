package com.tracelink.appsec.watchtower.core.scan.image.repository;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import com.tracelink.appsec.watchtower.core.scan.IViolationRepository;
import com.tracelink.appsec.watchtower.core.scan.image.entity.ImageScanEntity;
import com.tracelink.appsec.watchtower.core.scan.image.entity.ImageViolationEntity;

@Repository("imageViolationRepository")
public interface ImageViolationRepository extends IViolationRepository<ImageViolationEntity> {
	@Query("SELECT v.scan FROM ImageViolationEntity v GROUP BY v.scan")
	Page<ImageScanEntity> findAllGroupByScan(Pageable page);
}
