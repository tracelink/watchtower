package com.tracelink.appsec.watchtower.core.auth.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.tracelink.appsec.watchtower.core.auth.model.ApiKeyEntity;

/**
 * Repository for API Keys
 *
 * @author csmith
 */
@Repository
public interface ApiKeyRepository extends JpaRepository<ApiKeyEntity, Long> {

	/**
	 * Get an Api key given its api key id
	 *
	 * @param apiKeyId the key's id
	 * @return the entity, or null if not found
	 */
	ApiKeyEntity findByApiKeyId(String apiKeyId);

}
