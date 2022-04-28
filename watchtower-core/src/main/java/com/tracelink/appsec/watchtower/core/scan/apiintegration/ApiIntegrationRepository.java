package com.tracelink.appsec.watchtower.core.scan.apiintegration;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

/**
 * Repository JPA for the API integration entities
 *
 * @author csmith
 */
@Repository(value = "apiIntegrationRepo")
public interface ApiIntegrationRepository extends JpaRepository<ApiIntegrationEntity, Long> {

	ApiIntegrationEntity findByApiLabel(String apiLabel);

}
