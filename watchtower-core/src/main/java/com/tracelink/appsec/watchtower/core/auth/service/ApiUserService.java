package com.tracelink.appsec.watchtower.core.auth.service;

import com.tracelink.appsec.watchtower.core.auth.model.ApiKeyEntity;
import com.tracelink.appsec.watchtower.core.auth.model.UserEntity;
import com.tracelink.appsec.watchtower.core.auth.repository.ApiKeyRepository;
import java.security.KeyException;
import java.util.Collections;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

/**
 * CRUD operations for Api Keys for users
 *
 * @author csmith
 */
@Service
public class ApiUserService implements UserDetailsService {

	private final ApiKeyRepository apiKeyRepository;
	private final UserService userService;
	private final PasswordEncoder passwordEncoder;

	public ApiUserService(@Autowired ApiKeyRepository apiKeyRepository,
			@Autowired UserService userService,
			@Autowired PasswordEncoder passwordEncoder) {
		this.apiKeyRepository = apiKeyRepository;
		this.userService = userService;
		this.passwordEncoder = passwordEncoder;
	}

	/**
	 * Load the associated principal for this apiKeyId. If the API key is associated with a user,
	 * the user generated has the associated user's username and authorities. Otherwise, it has no
	 * authorities and the username is the apiKeyId.
	 * <p>
	 * {@inheritDoc}
	 *
	 * @param apiKeyId an api key id
	 * @throws UsernameNotFoundException if the api key is unknown
	 */
	@Override
	public UserDetails loadUserByUsername(String apiKeyId) throws UsernameNotFoundException {
		ApiKeyEntity apiKeyEntity = findByApiKeyId(apiKeyId);
		if (apiKeyEntity == null) {
			throw new UsernameNotFoundException("Unknown Api Key");
		}
		UserEntity user = apiKeyEntity.getUser();
		if (user != null) {
			return userService.buildUser(user.getUsername(), apiKeyEntity.getSecret(), user);
		} else {
			return User.builder().username(apiKeyId).password(apiKeyEntity.getSecret())
					.authorities(Collections.emptyList()).disabled(false).build();
		}
	}

	private ApiKeyEntity findByApiKeyId(String apiKeyId) {
		return apiKeyRepository.findByApiKeyId(apiKeyId);
	}

	/**
	 * Generates a new random api key and secret for a user. API Key ID is guaranteed to be unique.
	 * The object returned contains both the hashed secret ID, and a plaintext secret id under the
	 * {@linkplain ApiKeyEntity#getFirstTimeSecret()} method. After this, only the hashed secret id
	 * is available.
	 *
	 * @param apiKeyLabel the "name" of this api key as chosen by the user
	 * @param user        the user to attach this key to
	 * @return a new api key entity with a unique random api key id for the given user
	 */
	public ApiKeyEntity createUserApiKey(String apiKeyLabel, UserEntity user) {
		ApiKeyEntity apiKeyEntity = new ApiKeyEntity();
		String apiKeyId;
		do {
			apiKeyId = UUID.randomUUID().toString();
		} while (findByApiKeyId(apiKeyId) != null);

		String secretKey = UUID.randomUUID().toString();
		apiKeyEntity.setApiKeyId(apiKeyId);
		apiKeyEntity.setKeyLabel(apiKeyLabel);
		apiKeyEntity.setFirstTimeSecret(secretKey);
		apiKeyEntity.setSecret(passwordEncoder.encode(secretKey));
		apiKeyEntity.setUser(user);
		return apiKeyRepository.saveAndFlush(apiKeyEntity);
	}

	/**
	 * Creates a programmatic API key that is not associated with a particular user and has the
	 * given apiKeyLabel.
	 *
	 * @param apiKeyLabel the label for the new API key
	 * @return new programmatic API key
	 */
	public ApiKeyEntity createProgrammaticApiKey(String apiKeyLabel) {
		ApiKeyEntity apiKeyEntity = new ApiKeyEntity();
		String apiKeyId;
		do {
			apiKeyId = UUID.randomUUID().toString();
		} while (findByApiKeyId(apiKeyId) != null);

		String secretKey = UUID.randomUUID().toString();
		apiKeyEntity.setKeyLabel(apiKeyLabel);
		apiKeyEntity.setApiKeyId(apiKeyId);
		apiKeyEntity.setFirstTimeSecret(secretKey);
		apiKeyEntity.setSecret(passwordEncoder.encode(secretKey));
		return apiKeyRepository.saveAndFlush(apiKeyEntity);
	}

	/**
	 * Given an api key id and user, delete the key if the key is for the user
	 *
	 * @param apiKeyId the key id for an api key
	 * @param user     the user associated with the given api key
	 * @throws KeyException if the key id is not found in the user's list of keys
	 */
	public void deleteUserApiKey(String apiKeyId, UserEntity user) throws KeyException {
		ApiKeyEntity apiKey = user.getApiKeys().stream()
				.filter(k -> k.getApiKeyId().equals(apiKeyId)).findFirst()
				.orElseThrow(() -> new KeyException("Key ID does not match User API Key"));
		user.getApiKeys().remove(apiKey);
		userService.updateUser(user);
		apiKeyRepository.delete(apiKey);
		apiKeyRepository.flush();
	}

	/**
	 * Deletes the programmatic API key with the given key label.
	 *
	 * @param keyLabel the label of the API key to delete
	 */
	public void deleteProgrammaticApiKey(String keyLabel) {
		ApiKeyEntity apiKey = apiKeyRepository.findByKeyLabelAndUserIsNull(keyLabel);
		apiKeyRepository.delete(apiKey);
		apiKeyRepository.flush();
	}

	/**
	 * Authorizes requests made with an API integration key. Checks that the given key label matches
	 * the key label of the API key for the authenticated principal.
	 *
	 * @param authentication the authentication of the current principal
	 * @param keyLabel       the key label to check
	 * @return true if the key labels are equal, false otherwise
	 */
	public boolean authorizeApiIntegrationRequest(Authentication authentication, String keyLabel) {
		ApiKeyEntity apiKey = apiKeyRepository.findByApiKeyId(authentication.getName());
		if (apiKey == null) {
			return false;
		}
		return apiKey.getKeyLabel().equals(keyLabel);
	}
}
