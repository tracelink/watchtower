package com.tracelink.appsec.watchtower.core.scan.image.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.tracelink.appsec.watchtower.core.scan.image.entity.ImageContainerEntity;

@Repository
public interface ImageContainerRepository extends JpaRepository<ImageContainerEntity, Long> {

	ImageContainerEntity findByRegistryNameAndImageNameAndTagName(String registry, String image,
			String tag);

}
