package com.tracelink.appsec.watchtower.core.scan.apiintegration;

import com.tracelink.appsec.watchtower.core.auth.service.ApiUserService;
import com.tracelink.appsec.watchtower.core.scan.IWatchtowerApi;
import java.util.Arrays;
import java.util.List;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

/**
 * Handles all logic related to the API Integration Entities
 *
 * @author csmith
 */
@Service
public class ApiIntegrationService {

	private final ApiIntegrationRepository apiRepo;
	private final ApiUserService apiUserService;

	public ApiIntegrationService(@Autowired ApiIntegrationRepository apiRepo,
			@Autowired ApiUserService apiUserService) {
		this.apiRepo = apiRepo;
		this.apiUserService = apiUserService;
	}

	/**
	 * Update or add this entity
	 *
	 * @param entity the entity to save
	 */
	public void save(ApiIntegrationEntity entity) {
		if (!entity.getApiLabel().matches("[a-zA-Z0-9]+")) {
			throw new IllegalArgumentException("API Label must be alpha-numeric");
		}
		apiRepo.saveAndFlush(entity);
	}

	/**
	 * Update or insert a new entity given an entity object. Updates will occur if an entity exists
	 * using the incoming entity's ID
	 *
	 * @param apiIntegrationEntity the entity definition
	 * @throws IllegalArgumentException if the entity cannot be saved
	 */
	public void upsertEntity(ApiIntegrationEntity apiIntegrationEntity) {
		ApiIntegrationEntity savedEntity = findByLabel(apiIntegrationEntity.getApiLabel());
		if (savedEntity != null) {
			if (apiIntegrationEntity.getIntegrationId() != savedEntity.getIntegrationId()) {
				throw new IllegalArgumentException(
						"There is already an API integration with this label");
			}
		}
		save(apiIntegrationEntity);
	}

	/**
	 * If an integration entity with this api label exists and it is not in a registered state,
	 * delete it from the backend
	 *
	 * @param apiLabel the api label of the integration entity to delete from the backend
	 * @throws ApiIntegrationException if the entity is not in a state where it can be deleted
	 */
	public void delete(String apiLabel) throws ApiIntegrationException {
		// Get integration entity for given label
		ApiIntegrationEntity integrationEntity = apiRepo.findByApiLabel(apiLabel);
		if (integrationEntity == null) {
			return;
		}
		// Ensure that integration entity is in a valid state
		if (!Arrays.asList(RegisterState.NOT_SUPPORTED, RegisterState.NOT_REGISTERED)
				.contains(integrationEntity.getRegisterState())) {
			throw new ApiIntegrationException("API integration cannot be deleted in state "
					+ integrationEntity.getRegisterState().getDisplayName());
		}
		apiRepo.delete(integrationEntity);
		apiRepo.flush();
	}

	/**
	 * Get the API Entity by its id
	 *
	 * @param apiId the api id
	 * @return an {@linkplain ApiIntegrationEntity} for the id or null
	 */
	public ApiIntegrationEntity findById(long apiId) {
		return apiRepo.findById(apiId).orElse(null);
	}

	/**
	 * Get the API Entity by its label
	 *
	 * @param label the api label
	 * @return an {@linkplain ApiIntegrationEntity} for the label or null
	 */
	public ApiIntegrationEntity findByLabel(String label) {
		return apiRepo.findByApiLabel(label);
	}

	/**
	 * Get all integration entities from the backend
	 *
	 * @return a List of Entities
	 */
	public List<ApiIntegrationEntity> getAllSettings() {
		return apiRepo.findAll();
	}

	/**
	 * Registers a Watchtower scan webhook with the remote service associated with the given API
	 * integration label.
	 *
	 * @param apiLabel the apiLabel of the integration entity to register a webhook for
	 * @throws ApiIntegrationException if there is no integration entity with the given label or if
	 *                                 the integration entity is in a state where it cannot be
	 *                                 registered
	 */
	public void register(String apiLabel) throws ApiIntegrationException {
		// Get integration entity for given label
		ApiIntegrationEntity integrationEntity = apiRepo.findByApiLabel(apiLabel);
		if (integrationEntity == null) {
			throw new ApiIntegrationException("Unknown API integration label");
		}
		// Ensure that integration entity is in a valid state
		if (!integrationEntity.getRegisterState().equals(RegisterState.NOT_REGISTERED)) {
			throw new ApiIntegrationException("API integration cannot be registered in state "
					+ integrationEntity.getRegisterState().getDisplayName());
		}
		// Create API and register
		IWatchtowerApi api = integrationEntity.createApi();
		api.register(apiUserService::createProgrammaticApiKey, apiRepo::saveAndFlush);
	}

	/**
	 * Unregisters a Watchtower scan webhook with the remote service associated with the given API
	 * integration label.
	 *
	 * @param apiLabel the apiLabel of the integration entity to unregister a webhook for
	 * @throws ApiIntegrationException if there is no integration entity with the given label or if
	 *                                 the integration entity is in a state where it cannot be
	 *                                 registered
	 */
	public void unregister(String apiLabel) throws ApiIntegrationException {
		// Get integration entity for given label
		ApiIntegrationEntity integrationEntity = apiRepo.findByApiLabel(apiLabel);
		if (integrationEntity == null) {
			throw new ApiIntegrationException("Unknown API integration label");
		}
		// Ensure that integration entity is in a valid state
		if (!Arrays.asList(RegisterState.REGISTERED, RegisterState.FAILED)
				.contains(integrationEntity.getRegisterState())) {
			throw new ApiIntegrationException("API integration cannot be unregistered in state "
					+ integrationEntity.getRegisterState().getDisplayName());
		}
		// Create API and register
		IWatchtowerApi api = integrationEntity.createApi();
		api.unregister(apiUserService::deleteProgrammaticApiKey, this::upsertEntity);
	}

}