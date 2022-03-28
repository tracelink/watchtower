package com.tracelink.appsec.watchtower.core.scan.api.image.ecr;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository(value = "ecrIntegrationRepository")
public interface EcrIntegrationRepository extends
		JpaRepository<EcrIntegrationEntity, Long> {

}
