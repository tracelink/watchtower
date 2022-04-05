package com.tracelink.appsec.watchtower.core.scan.image.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.tracelink.appsec.watchtower.core.scan.image.entity.ImageScanEntity;

@Repository
public interface ImageScanRepository extends JpaRepository<ImageScanEntity, Long> {

}
