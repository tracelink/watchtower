package com.tracelink.appsec.watchtower.core.scan.image.repository;

import org.springframework.stereotype.Repository;

import com.tracelink.appsec.watchtower.core.scan.IContainerRepository;
import com.tracelink.appsec.watchtower.core.scan.image.entity.ImageScanContainerEntity;

@Repository("imageContainerRepository")
public interface ImageContainerRepository extends IContainerRepository<ImageScanContainerEntity> {

	ImageScanContainerEntity findOneByApiLabelAndImageNameAndTagName(String apiLabel,
			String imageName, String tagName);

}
