package com.tracelink.appsec.watchtower.core.auth.repository;

import com.tracelink.appsec.watchtower.core.auth.model.ApiKeyEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

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

	/**
	 * Get an API key with the given label that is not associated with any user
	 *
	 * @param keyLabel label of the API key
	 * @return API with given label and no user, otherwise null
	 */
	ApiKeyEntity findByKeyLabelAndUserIsNull(String keyLabel);

}
