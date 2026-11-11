package com.tracelink.appsec.watchtower.core.scan.apiintegration;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

/**
 * Repository JPA for the API integration entities
 *
 * @author csmith
 */
@Repository(value = "apiIntegrationRepo")
public interface ApiIntegrationRepository extends JpaRepository<ApiIntegrationEntity, Long> {

	ApiIntegrationEntity findByApiLabel(String apiLabel);

	/**
	 * Records the last connection check without loading or rewriting the integration (whose
	 * secrets the update flow treats carefully).
	 *
	 * @return 1 if the integration exists
	 */
	@Modifying(clearAutomatically = true, flushAutomatically = true)
	@Transactional
	@Query("UPDATE ApiIntegrationEntity e SET e.healthCheckedAt = :checkedAt,"
			+ " e.healthOk = :ok, e.healthError = :error WHERE e.apiLabel = :apiLabel")
	int recordHealth(@Param("apiLabel") String apiLabel, @Param("checkedAt") long checkedAt,
			@Param("ok") boolean ok, @Param("error") String error);

}
