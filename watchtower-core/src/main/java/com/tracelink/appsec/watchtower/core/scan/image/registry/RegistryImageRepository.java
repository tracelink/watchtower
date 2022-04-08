package com.tracelink.appsec.watchtower.core.scan.image.registry;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository("registryImageRepository")
public interface RegistryImageRepository extends JpaRepository<RegistryImageEntity, Long> {

	RegistryImageEntity findByApiLabelAndImageName(String apiLabel, String imageName);


}
