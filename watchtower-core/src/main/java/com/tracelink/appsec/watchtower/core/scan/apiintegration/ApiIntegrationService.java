package com.tracelink.appsec.watchtower.core.scan.apiintegration;

import java.util.Arrays;
import java.util.List;
import java.util.concurrent.CompletableFuture;

import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.scheduling.annotation.Async;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.tracelink.appsec.watchtower.core.scan.IWatchtowerApi;
import com.tracelink.appsec.watchtower.core.scan.code.scm.api.bb.BBCloudApi;
import com.tracelink.appsec.watchtower.core.scan.code.scm.api.bb.BBCloudIntegrationEntity;

/**
 * Handles all logic related to the API Integration Entities
 *
 * @author csmith
 */
@Service
public class ApiIntegrationService {

	private final ApiIntegrationRepository apiRepo;
	private final PasswordEncoder passwordEncoder;
	private final String publicUrl;
	private com.tracelink.appsec.watchtower.core.scan.apiintegration.webhook.BBWebhookManagementService webhooks;
	@Autowired
	public void setWebhooks(com.tracelink.appsec.watchtower.core.scan.apiintegration.webhook.BBWebhookManagementService webhooks){this.webhooks=webhooks;}
	private String actor(){var auth=org.springframework.security.core.context.SecurityContextHolder.getContext().getAuthentication();return auth==null?"system":auth.getName();}

	public ApiIntegrationService(@Autowired ApiIntegrationRepository apiRepo,
			@Autowired PasswordEncoder passwordEncoder,
			@Value("${watchtower.publicUrl:#{null}}") String publicUrl) {
		this.apiRepo = apiRepo;
		this.passwordEncoder = passwordEncoder;
		this.publicUrl = publicUrl;
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
	public void upsertEntity(ApiIntegrationEntity apiIntegrationEntity)
			throws IllegalArgumentException {
		ApiIntegrationEntity savedEntity = findByLabel(apiIntegrationEntity.getApiLabel());
		if (savedEntity != null) {
			if (apiIntegrationEntity.getIntegrationId() != savedEntity.getIntegrationId()) {
				throw new IllegalArgumentException(
						"There is already an API integration with this label");
			}
		}
		if(webhooks!=null && savedEntity instanceof BBCloudIntegrationEntity && apiIntegrationEntity instanceof BBCloudIntegrationEntity incoming) {
			webhooks.saveSettings(incoming);return;
		}
		save(apiIntegrationEntity);
	}

	/**
	 * If an integration entity with this api label exists and it is not in a registered state,
	 * delete it from the backend
	 *
	 * @param apiLabel the api label of the integration entity to delete from the backend
	 * @throws ApiIntegrationException if the entity is unknown or not in a state where it can be
	 *                                 deleted
	 */
	public void delete(String apiLabel) throws ApiIntegrationException {
		// Get integration entity for given label
		ApiIntegrationEntity integrationEntity = apiRepo.findByApiLabel(apiLabel);
		if (integrationEntity == null) {
			throw new ApiIntegrationException("Unknown API Label");
		}
		// Ensure that integration entity is in a valid state
		if (!Arrays.asList(RegisterState.NOT_SUPPORTED, RegisterState.NOT_REGISTERED,
				RegisterState.FAILED).contains(integrationEntity.getRegisterState())) {
			throw new ApiIntegrationException("API integration cannot be deleted in state "
					+ integrationEntity.getRegisterState().getDisplayName());
		}
		if(webhooks!=null && integrationEntity instanceof BBCloudIntegrationEntity){webhooks.deleteIntegration(integrationEntity.getIntegrationId());return;}
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

	public Page<ApiIntegrationEntity> getSettings(Pageable pageable) {
		return apiRepo.findAll(pageable);
	}

	/**
	 * Registers a Watchtower scan webhook with the remote service associated with the given API
	 * integration label.
	 *
	 * @param apiLabel the apiLabel of the integration entity to register a webhook for
	 * @return {@linkplain CompletableFuture} indicating the status of registration, if needed
	 * @throws ApiIntegrationException if there is no integration entity with the given label or if
	 *                                 the integration entity is in a state where it cannot be
	 *                                 registered
	 */
	public CompletableFuture<Void> register(String apiLabel) throws ApiIntegrationException {
		// Get integration entity for given label
		ApiIntegrationEntity integrationEntity = apiRepo.findByApiLabel(apiLabel);
		if (integrationEntity == null) {
			throw new ApiIntegrationException("Unknown API integration label");
		}
		if(webhooks!=null && integrationEntity instanceof BBCloudIntegrationEntity) {
			try {webhooks.enqueue(apiLabel,"UPSERT",com.tracelink.appsec.watchtower.core.scan.apiintegration.webhook.BBWebhookPreset.ALL,true,null,null,actor());}
			catch(RuntimeException e){throw new ApiIntegrationException(e.getMessage());}
			return CompletableFuture.completedFuture(null);
		}

		// Ensure that integration entity is in a valid state
		if (!integrationEntity.getRegisterState().equals(RegisterState.NOT_REGISTERED)) {
			throw new ApiIntegrationException("API integration cannot be registered in state "
					+ integrationEntity.getRegisterState().getDisplayName());
		}
		// Behind an internet-facing ALB, Watchtower cannot reliably infer its own externally
		// reachable url, so this is required configuration rather than something derived from
		// the request. Checked synchronously so a missing value fails immediately instead of
		// surfacing as an opaque FAILED state after the async call runs.
		if (StringUtils.isBlank(publicUrl)) {
			throw new ApiIntegrationException(
					"watchtower.publicUrl must be configured before an integration can be registered");
		}
		// Persist the signing key BEFORE Bitbucket can deliver a hook, including when a
		// successful remote creation is followed by a timeout or process restart.
		if (integrationEntity instanceof BBCloudIntegrationEntity bb) {
			new BBCloudApi(bb).ensureWebhookSecret();
		}
		integrationEntity.setRegisterError(null);
		// Set register state to in progress
		integrationEntity.setRegisterState(RegisterState.IN_PROGRESS);
		apiRepo.saveAndFlush(integrationEntity);

		// Create API and register
		IWatchtowerApi api = integrationEntity.createApi();
		return registerAsync(api).whenCompleteAsync((v, e) -> {
			if (e == null) {
				integrationEntity.setRegisterState(RegisterState.REGISTERED);
			} else {
				integrationEntity.setRegisterState(RegisterState.FAILED);
				integrationEntity.setRegisterError(e.getMessage());
			}
			upsertEntity(integrationEntity);
		});
	}

	@Async
	private CompletableFuture<Void> registerAsync(IWatchtowerApi api) {
		return CompletableFuture.runAsync(() -> api.register(passwordEncoder, publicUrl));
	}

	/**
	 * Unregisters a Watchtower scan webhook with the remote service associated with the given API
	 * integration label.
	 *
	 * @param apiLabel the apiLabel of the integration entity to unregister a webhook for
	 * @return {@linkplain CompletableFuture} indicating the status of unregistration, if needed
	 * @throws ApiIntegrationException if there is no integration entity with the given label or if
	 *                                 the integration entity is in a state where it cannot be
	 *                                 registered
	 */
	public CompletableFuture<Void> unregister(String apiLabel) throws ApiIntegrationException {
		// Get integration entity for given label
		ApiIntegrationEntity integrationEntity = apiRepo.findByApiLabel(apiLabel);
		if (integrationEntity == null) {
			throw new ApiIntegrationException("Unknown API integration label");
		}
		if(webhooks!=null && integrationEntity instanceof BBCloudIntegrationEntity bb) {
			try {webhooks.enqueue(apiLabel,"DELETE",com.tracelink.appsec.watchtower.core.scan.apiintegration.webhook.BBWebhookPreset.ALL,true,null,bb.getWebhookUuid(),actor());}
			catch(RuntimeException e){throw new ApiIntegrationException(e.getMessage());}
			return CompletableFuture.completedFuture(null);
		}

		// Ensure that integration entity is in a valid state
		if (!Arrays.asList(RegisterState.REGISTERED, RegisterState.FAILED)
				.contains(integrationEntity.getRegisterState())) {
			throw new ApiIntegrationException("API integration cannot be unregistered in state "
					+ integrationEntity.getRegisterState().getDisplayName());
		}
		// Set register status to unregistered and delete error if it is set
		integrationEntity.setRegisterState(RegisterState.IN_PROGRESS);
		integrationEntity.setRegisterError(null);
		apiRepo.saveAndFlush(integrationEntity);

		// Create API and unregister
		IWatchtowerApi api = integrationEntity.createApi();
		return unregisterAsync(api).whenCompleteAsync((v, e) -> {
			if (e == null) {
				integrationEntity.setRegisterState(RegisterState.NOT_REGISTERED);
			} else {
				integrationEntity.setRegisterState(RegisterState.FAILED);
				integrationEntity.setRegisterError(e.getMessage());
			}
			upsertEntity(integrationEntity);
		});
	}

	@Async
	private CompletableFuture<Void> unregisterAsync(IWatchtowerApi api) {
		return CompletableFuture.runAsync(api::unregister);
	}

}
