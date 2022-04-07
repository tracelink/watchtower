package com.tracelink.appsec.watchtower.core.scan.image.repository;

import org.springframework.stereotype.Repository;

import com.tracelink.appsec.watchtower.core.scan.IViolationRepository;
import com.tracelink.appsec.watchtower.core.scan.image.entity.ImageViolationEntity;

@Repository("imageViolationRepository")
public interface ImageViolationRepository extends IViolationRepository<ImageViolationEntity> {

}
