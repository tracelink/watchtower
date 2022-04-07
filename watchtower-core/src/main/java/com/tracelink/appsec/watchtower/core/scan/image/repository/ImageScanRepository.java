package com.tracelink.appsec.watchtower.core.scan.image.repository;

import org.springframework.stereotype.Repository;

import com.tracelink.appsec.watchtower.core.scan.IScanRepository;
import com.tracelink.appsec.watchtower.core.scan.image.entity.ImageScanEntity;

@Repository("imageScanRepository")
public interface ImageScanRepository extends IScanRepository<ImageScanEntity> {

}
