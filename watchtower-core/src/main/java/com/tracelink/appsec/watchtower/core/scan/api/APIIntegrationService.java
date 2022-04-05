package com.tracelink.appsec.watchtower.core.scan.api;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

/**
 * Handles all logic related to the API Integration Entities
 *
 * @author csmith
 */
@Service
public class APIIntegrationService {

	private APIIntegrationRepository apiRepo;

	public APIIntegrationService(@Autowired APIIntegrationRepository apiRepo) {
		this.apiRepo = apiRepo;
	}

	/**
	 * Update or add this entity
	 *
	 * @param entity the entity to save
	 * @throws ApiIntegrationException if the entity cannot be saved
	 */
	public void save(APIIntegrationEntity entity) throws ApiIntegrationException {
		if (!entity.getApiLabel().matches("[a-zA-Z0-9]+")) {
			throw new ApiIntegrationException("API Label must be alpha-numeric");
		}
		apiRepo.saveAndFlush(entity);
	}

	/**
	 * Update or insert a new entity given an entity object. Updates will occur if an entity exists
	 * using the incoming entity's ID
	 * 
	 * @param incomingEntity the entity definition
	 * @throws ApiIntegrationException if the entity cannot be saved
	 */
	public void upsertEntity(APIIntegrationEntity incomingEntity) throws ApiIntegrationException {
		APIIntegrationEntity oldEntity = findById(incomingEntity.getIntegrationId());
		if (oldEntity != null) {
			incomingEntity.setIntegrationId(oldEntity.getIntegrationId());
		}
		save(incomingEntity);
	}

	/**
	 * If this entity exists, delete it from the backend
	 *
	 * @param entity the entity to delete from the backend
	 */
	public void delete(APIIntegrationEntity entity) {
		APIIntegrationEntity savedEntity = apiRepo.getByApiLabel(entity.getApiLabel());
		if (savedEntity == null) {
			return;
		}
		apiRepo.delete(savedEntity);
		apiRepo.flush();
	}

	/**
	 * Get the API Entity by its id
	 * 
	 * @param apiId the api id
	 * @return an {@linkplain APIIntegrationEntity} for the id or null
	 */
	public APIIntegrationEntity findById(long apiId) {
		return apiRepo.findById(apiId).orElse(null);
	}

	/**
	 * Get the API Entity by its label
	 * 
	 * @param label the api label
	 * @return an {@linkplain APIIntegrationEntity} for the label or null
	 */
	public APIIntegrationEntity findByLabel(String label) {
		return apiRepo.getByApiLabel(label);
	}

	/**
	 * Get all integration entities from the backend
	 *
	 * @return a List of Entities
	 */
	public List<APIIntegrationEntity> getAllSettings() {
		return apiRepo.findAll();
	}



}
