package com.tracelink.appsec.watchtower.core.encryption.service;

import java.security.Key;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import javax.annotation.PostConstruct;
import javax.annotation.PreDestroy;
import javax.persistence.Convert;
import javax.persistence.EntityManagerFactory;

import org.hibernate.event.service.spi.EventListenerRegistry;
import org.hibernate.event.spi.EventType;
import org.hibernate.internal.SessionFactoryImpl;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.context.event.EventListener;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.repository.support.Repositories;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.web.context.WebApplicationContext;

import com.tracelink.appsec.watchtower.core.encryption.controller.EncryptionMgmtController;
import com.tracelink.appsec.watchtower.core.encryption.converter.AbstractEncryptedAttributeConverter;
import com.tracelink.appsec.watchtower.core.encryption.listener.EncryptionFlushEntityEventListener;
import com.tracelink.appsec.watchtower.core.encryption.model.DataEncryptionKey;
import com.tracelink.appsec.watchtower.core.encryption.model.EncryptionMetadata;
import com.tracelink.appsec.watchtower.core.encryption.model.EncryptionType;
import com.tracelink.appsec.watchtower.core.encryption.repository.DataEncryptionKeyRepository;
import com.tracelink.appsec.watchtower.core.encryption.repository.EncryptionMetadataRepository;
import com.tracelink.appsec.watchtower.core.encryption.utils.EncryptionUtils;

/**
 * Service to handle rotation of key encryption keys and data encryption keys. Interacts with the
 * {@link DataEncryptionKeyRepository} to access the data encryption keys stored in the database and
 * the {@link KeyEncryptionService} to determine whether to rotate the key encryption key or to
 * decrypt the entire database. This service also manages the {@link EncryptionMetadataRepository}
 * and handles interactions to schedule and configure auto-rotation of data encryption keys.
 *
 * @author mcool
 */
@Service
public class KeyRotationService {

	private static final Logger LOGGER = LoggerFactory.getLogger(DataEncryptionService.class);
	private static final String UNKNOWN_ENC_TYPE = "Unknown encryption type: ";

	private final EncryptionType encryptionType;
	private final boolean decryptMode;
	private final DataEncryptionKeyRepository dataEncryptionKeyRepository;
	private final KeyEncryptionService keyEncryptionService;
	private final EncryptionMetadataRepository encryptionMetadataRepository;

	private final Repositories repositories;
	private final EntityManagerFactory entityManagerFactory;
	private final EncryptionFlushEntityEventListener encryptionFlushEntityEventListener;

	private final Map<Class<?>, Set<String>> annotationsCache = new HashMap<>();

	public KeyRotationService(
			@Value("${watchtower.encryption.type:none}") EncryptionType encryptionType,
			@Value("${watchtower.encryption.environment.decryptMode:#{false}}") boolean decryptMode,
			@Autowired DataEncryptionKeyRepository dataEncryptionKeyRepository,
			@Autowired KeyEncryptionService keyEncryptionService,
			@Autowired EncryptionMetadataRepository encryptionMetadataRepository,
			@Autowired WebApplicationContext webApplicationContext,
			@Autowired EntityManagerFactory entityManagerFactory,
			@Autowired EncryptionFlushEntityEventListener encryptionFlushEntityEventListener) {
		this.encryptionType = encryptionType;
		this.decryptMode = decryptMode;
		this.dataEncryptionKeyRepository = dataEncryptionKeyRepository;
		this.keyEncryptionService = keyEncryptionService;
		this.encryptionMetadataRepository = encryptionMetadataRepository;
		this.repositories = new Repositories(webApplicationContext);
		this.entityManagerFactory = entityManagerFactory;
		this.encryptionFlushEntityEventListener = encryptionFlushEntityEventListener;
	}

	/**
	 * Initializes the key rotation service depending on the {@link EncryptionType}.
	 *
	 * @throws IllegalArgumentException if an unknown encryption type is provided
	 */
	@PostConstruct
	public void postConstruct() throws IllegalArgumentException {
		switch (encryptionType) {
			case ENVIRONMENT:
				// Configure flush entity event listener to handle key rotation
				configureEncryptionFlushEntityEventListener();
				// Initialize encryption metadata, if it has not already been done
				initializeEncryptionMetadata();
				// Perform key encryption key rotation, if needed
				handleKeyEncryptionKeyRotation();
				// Populate the annotations cache
				populateAnnotationsCache();
				break;
			case NONE:
				break;
			default:
				throw new IllegalArgumentException(UNKNOWN_ENC_TYPE + encryptionType);
		}
	}

	/**
	 * If {@code decryptMode} is enabled, deletes all data encryption keys from the database before
	 * Watchtower shuts down.
	 *
	 * @throws IllegalArgumentException if an unknown encryption type is provided
	 */
	@PreDestroy
	public void preDestroy() throws IllegalArgumentException {
		switch (encryptionType) {
			case ENVIRONMENT:
				if (decryptMode) {
					// Delete all data encryption keys and encryption metadata
					finalizeDecryption();
				}
				break;
			case NONE:
				break;
			default:
				throw new IllegalArgumentException(UNKNOWN_ENC_TYPE + encryptionType);
		}
	}

	/**
	 * Handles startup actions that can only be completed once the entire application has come up.
	 * The actions performed depend on the {@link EncryptionType}.
	 *
	 * @param event context refreshed event that occurs after all plugins have been loaded
	 * @throws IllegalArgumentException if an unknown encryption type is provided.
	 */
	@EventListener
	public void onApplicationEvent(ContextRefreshedEvent event) throws IllegalArgumentException {
		switch (encryptionType) {
			case ENVIRONMENT:
				// Check each data encryption key to recover if we are mid-rotation
				completeDataEncryptionKeyRotations();
				if (decryptMode) {
					// Decrypt entire database, if configured
					decryptAllData();
				} else {
					// Generate new data encryption keys as needed and encrypt existing data for the
					// first time
					encryptAddedColumns();
				}
				break;
			case NONE:
				break;
			default:
				throw new IllegalArgumentException(UNKNOWN_ENC_TYPE + encryptionType);
		}
	}

	/**
	 * Gets all the {@link DataEncryptionKey}s that are stored in the database.
	 *
	 * @return unmodifiable list of data encryption keys
	 */
	public List<DataEncryptionKey> getKeys() {
		return Collections.unmodifiableList(dataEncryptionKeyRepository.findAll());
	}

	/*
	 * Key rotation methods
	 */

	/**
	 * Rotates all the {@link DataEncryptionKey}s stored in the database. If any key already has a
	 * rotation in progress or is disabled, this method will skip rotation for that key. This method
	 * is called asynchronously from the {@link EncryptionMgmtController}, but only one key is
	 * rotated at a time.
	 */
	public void rotateKeys() {
		List<DataEncryptionKey> dataEncryptionKeys = dataEncryptionKeyRepository.findAll();
		dataEncryptionKeys.forEach(dataEncryptionKey -> {
			// Do not rotate if key rotation is already in progress or if key is disabled
			if (dataEncryptionKey.isRotationInProgress() || dataEncryptionKey.isDisabled()) {
				LOGGER.info("Skipping key rotation for converter " + dataEncryptionKey
						.getConverterClassName());
				return;
			}
			this.rotateKey(dataEncryptionKey);
		});
	}

	/**
	 * Rotates the {@link DataEncryptionKey} with the given id. If there is no key with the given
	 * id, if the key already has a rotation in progress or if the key is disabled, this method will
	 * skip rotation.
	 *
	 * @param keyId id of the {@link DataEncryptionKey} to rotate
	 */
	public void rotateKey(long keyId) {
		Optional<DataEncryptionKey> optionalDataEncryptionKey = dataEncryptionKeyRepository
				.findById(keyId);
		if (!optionalDataEncryptionKey.isPresent()) {
			LOGGER.info("Skipping key rotation: no data encryption key found with the given id");
			return;
		}
		DataEncryptionKey dataEncryptionKey = optionalDataEncryptionKey.get();
		// Do not rotate if key rotation is already in progress or if key is disabled
		if (dataEncryptionKey.isRotationInProgress() || dataEncryptionKey.isDisabled()) {
			LOGGER.info("Skipping key rotation for converter " + dataEncryptionKey
					.getConverterClassName());
			return;
		}
		this.rotateKey(dataEncryptionKey);
	}

	/**
	 * Rotates the given {@link DataEncryptionKey}. There are three stages to a key rotation. In the
	 * first stage, a new key is generated to replace the current key, the {@code
	 * rotationInProgress} boolean is set to true and the {@code lastRotationDateTime} is updated.
	 * The data encryption key is then saved in the database to ensure recovery if Watchtower goes
	 * down during the rotation. In the second stage, all entities that use the converter class
	 * associated with the given data encryption key are updated to re-encrypt the data with the new
	 * key. In the third stage, the {@code rotationInProgress} boolean is set to false and the data
	 * encryption key is saved again to complete the key rotation.
	 * <p>
	 * Note that if a key is passed to this method that already has a rotation in progress, the
	 * first stage is skipped, and a new key is not generated to replace the current key. This
	 * feature makes this method extremely versatile. It can be used to perform a normal key
	 * rotation, or it can be used to complete an unfinished key rotation on start-up. It can also
	 * be used to encrypt existing data for the very first time, or even to decrypt data that relies
	 * on the given data encryption key. The exact encryption and decryption logic for those
	 * scenarios is handled by the {@link DataEncryptionService}, but they are all triggered from
	 * this method.
	 *
	 * @param dataEncryptionKey the data encryption key to rotate
	 */
	private void rotateKey(DataEncryptionKey dataEncryptionKey) {
		LOGGER.info("Starting data encryption key rotation for converter " + dataEncryptionKey
				.getConverterClassName());
		if (!dataEncryptionKey.isRotationInProgress()) {
			// Update current and previous keys
			dataEncryptionKey.setPreviousKey(dataEncryptionKey.getCurrentKey());
			Key currentKey = EncryptionUtils.generateKey();
			dataEncryptionKey.setCurrentKey(currentKey);

			// Save state to start key rotation process and be able to recover from shutdown
			dataEncryptionKey.setRotationInProgress(true);
			dataEncryptionKey.setLastRotationDateTime(LocalDateTime.now());
			dataEncryptionKeyRepository.saveAndFlush(dataEncryptionKey);
		}

		// Update all entities that use the converter class for this key
		updateEntitiesWithConverter(dataEncryptionKey.getConverterClassName());

		// Finish key rotation process
		dataEncryptionKey.setRotationInProgress(false);
		dataEncryptionKeyRepository.saveAndFlush(dataEncryptionKey);
		LOGGER.info("Finished data encryption key rotation for converter " + dataEncryptionKey
				.getConverterClassName());
	}

	/**
	 * Updates all entities with attributes encrypted by the attribute converter class whose name
	 * matches the given string. Uses the annotation cache to update the entities for each entity
	 * class.
	 *
	 * @param converterClassName name of the attribute converter class
	 */
	private void updateEntitiesWithConverter(String converterClassName) {
		// For each entity class, get all @Convert annotations
		annotationsCache.forEach((entityClass, converterClassNames) -> {
			// If any use the given converter, update the entities for that entity class
			if (converterClassNames.contains(converterClassName)) {
				updateEntities(entityClass);
			}
		});
	}

	/**
	 * Updates all entities of the given entity class. Performs a
	 * {@link JpaRepository#findAll(Pageable)} and a {@link JpaRepository#saveAll(Iterable)} for
	 * each page of entities to re-encrypt the data with a new key. Pages contain up to 50 entities
	 * at a time.
	 *
	 * @param entityClass class of the entities to be updated
	 * @param <T>         type of the entity
	 */
	private <T> void updateEntities(Class<T> entityClass) {
		Optional<Object> optionalRepository = repositories.getRepositoryFor(entityClass);
		if (optionalRepository.isPresent()) {
			@SuppressWarnings(value = "unchecked")
			JpaRepository<T, ?> repository = (JpaRepository<T, ?>) optionalRepository.get();
			// Loop through all pages of entities to encrypt with current key
			Pageable pageable = PageRequest.of(0, 50);
			Page<T> page = repository.findAll(pageable);
			repository.saveAll(page.getContent());
			while (page.hasNext()) {
				pageable = pageable.next();
				page = repository.findAll(pageable);
				repository.saveAll(page.getContent());
			}
			repository.flush();
		} else {
			LOGGER.info("Found entity class " + entityClass.getName()
					+ " with @Convert annotation but cannot get associated repository.");
		}
	}

	/*
	 * Post Construct methods
	 */

	/**
	 * Configures the {@link EncryptionFlushEntityEventListener}, which is necessary to perform key
	 * rotations. This method is called if Watchtower is configured with
	 * {@link EncryptionType#ENVIRONMENT}, but can also be called for {@link EncryptionType#NONE} if
	 * Watchtower is configured to decrypt all data in the database.
	 */
	private void configureEncryptionFlushEntityEventListener() {
		SessionFactoryImpl sessionFactory = entityManagerFactory.unwrap(SessionFactoryImpl.class);
		EventListenerRegistry registry = sessionFactory.getServiceRegistry()
				.getService(EventListenerRegistry.class);
		registry.getEventListenerGroup(EventType.FLUSH_ENTITY).clear();
		registry.getEventListenerGroup(EventType.FLUSH_ENTITY)
				.appendListener(encryptionFlushEntityEventListener);
	}

	/**
	 * Initializes the encryption metadata. If encryption metadata does not already exist, this
	 * method will create encryption metadata. Also sets the last rotation date for the key
	 * encryption key, if it has not already been initialized. This method is only called if
	 * Watchtower is configured with {@link EncryptionType#ENVIRONMENT}.
	 */
	private void initializeEncryptionMetadata() {
		EncryptionMetadata encryptionMetadata = getEncryptionMetadata();
		if (encryptionMetadata.getLastRotationDateTime() == null) {
			// Set the date of the last key encryption key rotation as now
			encryptionMetadata.setLastRotationDateTime(LocalDateTime.now());
			encryptionMetadataRepository.saveAndFlush(encryptionMetadata);
		}
	}

	/**
	 * Performs a rotation of the key encryption key by calling
	 * {@link DataEncryptionKeyRepository#findAll()} and a
	 * {@link DataEncryptionKeyRepository#saveAll(Iterable)} to re-encrypt the data encryption keys
	 * with the new key encryption key. This method is only called if Watchtower is configured with
	 * {@link EncryptionType#ENVIRONMENT}.
	 */
	private void handleKeyEncryptionKeyRotation() {
		if (keyEncryptionService.keyRotationInProgress()) {
			LOGGER.info("Starting key encryption key rotation");
			List<DataEncryptionKey> dataEncryptionKeys = dataEncryptionKeyRepository.findAll();
			dataEncryptionKeyRepository.saveAll(dataEncryptionKeys);
			dataEncryptionKeyRepository.flush();
			keyEncryptionService.finishKeyRotation();
			updateKeyEncryptionKeyLastRotationDate();
			LOGGER.info("Finished key encryption key rotation");
		}
	}

	/**
	 * Populates the annotations cache on startup for both {@link EncryptionType#NONE} and
	 * {@link EncryptionType#ENVIRONMENT}. The annotations cache is a static map from each entity
	 * class to the set of encrypted attribute converter class names. It improves performance during
	 * key rotations.
	 */
	private void populateAnnotationsCache() {
		// For each entity class, get all @Convert annotations
		for (Class<?> entityClass : repositories) {
			// Get all fields of entity class
			Set<String> convertClasses = Arrays.stream(entityClass.getDeclaredFields())
					// Flat map to all @Convert annotations on the field
					.map(field -> field.getAnnotationsByType(Convert.class)).flatMap(Arrays::stream)
					// Filter out converters that are not used for encryption
					.filter(convert -> AbstractEncryptedAttributeConverter.class
							.isAssignableFrom(convert.converter()))
					// Map to converter class
					.map(convert -> convert.converter().getName()).collect(Collectors.toSet());
			annotationsCache.put(entityClass, convertClasses);
		}
	}

	/*
	 * Pre Destroy methods
	 */

	/**
	 * Finalizes decryption of database columns by deleting all data encryption keys and encryption
	 * metadata. This method should only be invoked when Watchtower is configured with
	 * {@link EncryptionType#ENVIRONMENT} and {@code decryptMode}.
	 */
	private void finalizeDecryption() {
		LOGGER.info("Deleting data encryption keys");
		dataEncryptionKeyRepository.deleteAll();
		dataEncryptionKeyRepository.flush();
		LOGGER.info("Deleting encryption metadata");
		encryptionMetadataRepository.deleteAll();
		encryptionMetadataRepository.flush();
	}

	/*
	 * Application Context Refreshed methods
	 */

	/**
	 * Completes any unfinished data encryption key rotations on startup. This method can only be
	 * called once all plugins have been initialized, or it will not be able to update all the
	 * entities.
	 */
	private void completeDataEncryptionKeyRotations() {
		List<DataEncryptionKey> dataEncryptionKeys = dataEncryptionKeyRepository.findAll();
		dataEncryptionKeys.stream().filter(DataEncryptionKey::isRotationInProgress)
				.forEach(dataEncryptionKey -> {
					LOGGER.info("Recovering from unfinished key rotation for converter "
							+ dataEncryptionKey.getConverterClassName());
					rotateKey(dataEncryptionKey);
				});
	}

	/**
	 * Ensures that any new columns added before startup are properly encrypted. Creates data
	 * encryption keys for converter classes in the annotation cache, if they don't already exist.
	 * Performs a key rotation for each key to encrypt any existing data for the first time. This
	 * method can only be called once all plugins have been initialized, or it will not be able to
	 * update database entities.
	 */
	private void encryptAddedColumns() {
		annotationsCache.values().stream().flatMap(Set::stream).distinct()
				.forEach(converterClassName -> {
					// If converter does not already have a data encryption key, create one
					Optional<DataEncryptionKey> optionalDataEncryptionKey =
							dataEncryptionKeyRepository
									.findByConverterClassName(converterClassName);
					if (optionalDataEncryptionKey.isPresent()) {
						// Rotate to encrypt any new columns annotated with this converter
						DataEncryptionKey dataEncryptionKey = optionalDataEncryptionKey.get();
						dataEncryptionKey.setRotationInProgress(true);
						dataEncryptionKey = dataEncryptionKeyRepository
								.saveAndFlush(dataEncryptionKey);
						rotateKey(dataEncryptionKey);
					} else {
						// Create new key for this converter and rotate to encrypt any existing data
						rotateKey(createDataEncryptionKey(converterClassName));
					}
				});
	}

	/**
	 * Creates a {@link DataEncryptionKey} for the given converter class name. Sets {@code
	 * rotationInProgress} to true to anticipate the initial key rotation after creation.
	 *
	 * @param converterClassName the name of the converter class for this key
	 * @return the data encryption key
	 */
	private DataEncryptionKey createDataEncryptionKey(String converterClassName) {
		DataEncryptionKey dataEncryptionKey = new DataEncryptionKey();
		dataEncryptionKey.setConverterClassName(converterClassName);
		dataEncryptionKey = dataEncryptionKeyRepository.saveAndFlush(dataEncryptionKey);
		return dataEncryptionKey;
	}

	/**
	 * Decrypts all data in the database that use encrypted attribute converters. This method is
	 * only called if Watchtower is configured with {@link EncryptionType#ENVIRONMENT} and {@code
	 * decryptMode} is true.
	 */
	private void decryptAllData() {
		LOGGER.info("Starting decryption of all database columns");
		List<DataEncryptionKey> dataEncryptionKeys = dataEncryptionKeyRepository.findAll();
		dataEncryptionKeys.forEach(dataEncryptionKey -> {
			dataEncryptionKey.setPreviousKey(dataEncryptionKey.getCurrentKey());
			dataEncryptionKey.setCurrentKey(null);
			dataEncryptionKey.setRotationInProgress(true);
			dataEncryptionKey.setDisabled(true);
			dataEncryptionKeyRepository.saveAndFlush(dataEncryptionKey);
			rotateKey(dataEncryptionKey);
		});
		LOGGER.info("Finished decryption of all database columns");
	}

	/*
	 * Encryption Metadata methods
	 */

	/**
	 * Gets the {@link EncryptionMetadata} object, or creates one if it doesn't exist.
	 *
	 * @return the encryption metadata
	 */
	public EncryptionMetadata getEncryptionMetadata() {
		List<EncryptionMetadata> encryptionMetadataList = encryptionMetadataRepository.findAll();
		EncryptionMetadata encryptionMetadata;
		if (encryptionMetadataList.isEmpty()) {
			encryptionMetadata = encryptionMetadataRepository
					.saveAndFlush(new EncryptionMetadata());
		} else {
			encryptionMetadata = encryptionMetadataList.get(0);
		}
		return encryptionMetadata;
	}

	/**
	 * Enables or disables auto-rotation of data encryption keys. If auto-rotation is enabled, the
	 * given rotation period must not be null and must be greater than zero. If auto-rotation is
	 * disabled, the rotation period will be set to null regardless of the given value.
	 *
	 * @param enable         whether to enable or disable auto-rotation
	 * @param rotationPeriod the period (in days) between rotations
	 * @throws IllegalArgumentException if the rotation period is invalid
	 */
	public void enableRotationSchedule(boolean enable, Integer rotationPeriod)
			throws IllegalArgumentException {
		// Make sure we have a valid rotation period to enable
		if (enable && (rotationPeriod == null || rotationPeriod <= 0)) {
			throw new IllegalArgumentException(
					"Please provide a rotation period greater than zero to enable scheduled rotations");
		}
		// Make sure rotation period is null to disable
		if (!enable && rotationPeriod != null) {
			rotationPeriod = null;
		}
		EncryptionMetadata encryptionMetadata = getEncryptionMetadata();
		encryptionMetadata.setRotationScheduleEnabled(enable);
		encryptionMetadata.setRotationPeriod(rotationPeriod);
		encryptionMetadataRepository.saveAndFlush(encryptionMetadata);
	}

	/**
	 * Updates the last rotation date of the key encryption key to now.
	 */
	private void updateKeyEncryptionKeyLastRotationDate() {
		EncryptionMetadata encryptionMetadata = getEncryptionMetadata();
		encryptionMetadata.setLastRotationDateTime(LocalDateTime.now());
		encryptionMetadataRepository.saveAndFlush(encryptionMetadata);
	}

	/**
	 * Rotates all data encryption keys that have not been rotated in the previous x days, where x
	 * is the rotation period configured in the {@link EncryptionMetadata}. If auto-rotation is not
	 * enabled or a rotation period is not set, this method does nothing.
	 */
	@Scheduled(cron = "0 0 0 * * *")
	private void autoRotateKeys() {
		EncryptionMetadata encryptionMetadata = getEncryptionMetadata();
		// If auto-rotation not correctly configured, does nothing
		if (!encryptionMetadata.isRotationScheduleEnabled()
				|| encryptionMetadata.getRotationPeriod() == null) {
			LOGGER.info("Auto-rotation not configured");
			return;
		}
		Integer rotationPeriod = encryptionMetadata.getRotationPeriod();
		List<DataEncryptionKey> dataEncryptionKeys = dataEncryptionKeyRepository
				.findAll();
		LocalDateTime now = LocalDate.now().atStartOfDay();
		// For each key, if the next rotation date is before now, perform key rotation
		dataEncryptionKeys.forEach(dataEncryptionKey -> {
			if (dataEncryptionKey.getLastRotationDateTime() != null) {
				LocalDateTime nextRotationDateTime = dataEncryptionKey
						.getLastRotationDateTime()
						.plus(rotationPeriod, ChronoUnit.DAYS);
				if (nextRotationDateTime.isBefore(now) && !dataEncryptionKey
						.isRotationInProgress() && !dataEncryptionKey.isDisabled()) {
					rotateKey(dataEncryptionKey);
				}
			}
		});
	}
}
