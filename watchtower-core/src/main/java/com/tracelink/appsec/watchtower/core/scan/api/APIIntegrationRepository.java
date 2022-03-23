package com.tracelink.appsec.watchtower.core.scan.api;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

/**
 * Repository JPA for the API integration entities
 *
 * @author csmith
 */
@Repository(value = "apiIntegrationRepo")
public interface APIIntegrationRepository extends JpaRepository<APIIntegrationEntity, Long> {

	APIIntegrationEntity getByApiLabel(String apiLabel);

	APIIntegrationEntity getByApiEndpoint(String apiEndpoint);

}
