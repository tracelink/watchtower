package com.tracelink.appsec.watchtower.core.encryption.service;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.security.Key;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import javax.persistence.Convert;
import javax.persistence.EntityManagerFactory;

import org.hibernate.event.service.spi.EventListenerGroup;
import org.hibernate.event.service.spi.EventListenerRegistry;
import org.hibernate.event.spi.EventType;
import org.hibernate.event.spi.FlushEntityEventListener;
import org.hibernate.internal.SessionFactoryImpl;
import org.hibernate.service.spi.ServiceRegistryImplementor;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.mockito.ArgumentCaptor;
import org.mockito.BDDMockito;
import org.mockito.Mockito;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Lazy;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.support.SimpleJpaRepository;
import org.springframework.data.repository.core.CrudMethods;
import org.springframework.data.repository.core.EntityInformation;
import org.springframework.data.repository.core.RepositoryInformation;
import org.springframework.data.repository.core.support.RepositoryFactoryInformation;
import org.springframework.data.util.Streamable;
import org.springframework.data.util.TypeInformation;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.util.ReflectionUtils;
import org.springframework.web.context.WebApplicationContext;

import com.tracelink.appsec.watchtower.core.encryption.converter.StringEncryptedAttributeConverter;
import com.tracelink.appsec.watchtower.core.encryption.listener.EncryptionFlushEntityEventListener;
import com.tracelink.appsec.watchtower.core.encryption.model.DataEncryptionKey;
import com.tracelink.appsec.watchtower.core.encryption.model.EncryptionMetadata;
import com.tracelink.appsec.watchtower.core.encryption.model.EncryptionType;
import com.tracelink.appsec.watchtower.core.encryption.repository.DataEncryptionKeyRepository;
import com.tracelink.appsec.watchtower.core.encryption.repository.EncryptionMetadataRepository;
import com.tracelink.appsec.watchtower.core.encryption.utils.EncryptionUtils;
import com.tracelink.appsec.watchtower.core.logging.CoreLogWatchExtension;

@ExtendWith(SpringExtension.class)
public class KeyRotationServiceTest {

	@RegisterExtension
	public final CoreLogWatchExtension logWatcher =
			CoreLogWatchExtension.forClass(DataEncryptionService.class);

	@MockBean
	private DataEncryptionKeyRepository dataEncryptionKeyRepository;

	@MockBean
	private KeyEncryptionService keyEncryptionService;

	@MockBean
	private EncryptionMetadataRepository encryptionMetadataRepository;

	@MockBean
	private WebApplicationContext webApplicationContext;

	@MockBean
	private EntityManagerFactory entityManagerFactory;

	@MockBean
	private EncryptionFlushEntityEventListener encryptionFlushEntityEventListener;

	private DataEncryptionKey dataEncryptionKey;

	@BeforeEach
	public void init() {
		@SuppressWarnings(value = "unchecked")
		RepositoryFactoryInformation<TestEntity, Long> repositoryFactoryInformation = BDDMockito
				.mock(RepositoryFactoryInformation.class);
		BDDMockito.when(repositoryFactoryInformation.getRepositoryInformation())
				.thenReturn(new TestRepositoryInformation());
		BDDMockito.when(repositoryFactoryInformation.getEntityInformation())
				.thenReturn(new TestEntityInformation());
		BDDMockito.when(webApplicationContext.getBean(TestRepository.class.getName(),
				RepositoryFactoryInformation.class)).thenReturn(repositoryFactoryInformation);
		BDDMockito.when(webApplicationContext
				.getBeanNamesForType(BDDMockito.any(Class.class), BDDMockito.anyBoolean(),
						BDDMockito.anyBoolean()))
				.thenReturn(new String[]{TestRepository.class.getName()});

		dataEncryptionKey = new DataEncryptionKey();
		dataEncryptionKey.setConverterClassName(TestConverter.class.getName());
		dataEncryptionKey.setCurrentKey(EncryptionUtils.generateKey());
		dataEncryptionKey.setLastRotationDateTime(LocalDateTime.now());
	}

	@Test
	public void testPostConstructEncryptionTypeNone() {
		KeyRotationService keyRotationService = new KeyRotationService(EncryptionType.NONE, false,
				dataEncryptionKeyRepository, keyEncryptionService, encryptionMetadataRepository,
				webApplicationContext, entityManagerFactory, encryptionFlushEntityEventListener);

		keyRotationService.postConstruct();

		BDDMockito.verify(entityManagerFactory, Mockito.times(0)).unwrap(SessionFactoryImpl.class);
		BDDMockito.verify(keyEncryptionService, Mockito.times(0)).keyRotationInProgress();
		BDDMockito.verify(keyEncryptionService, Mockito.times(0)).finishKeyRotation();
		BDDMockito.verify(dataEncryptionKeyRepository, Mockito.times(0)).findAll();
		BDDMockito.verify(dataEncryptionKeyRepository, Mockito.times(0))
				.saveAll(BDDMockito.anyIterable());
		BDDMockito.verify(dataEncryptionKeyRepository, Mockito.times(0)).flush();
	}

	@Test
	public void testPostConstructEncryptionTypeEnvironmentDecryptionConfigured() {
		KeyRotationService keyRotationService = new KeyRotationService(EncryptionType.ENVIRONMENT,
				true, dataEncryptionKeyRepository, keyEncryptionService,
				encryptionMetadataRepository, webApplicationContext, entityManagerFactory,
				encryptionFlushEntityEventListener);
		EventListenerGroup<FlushEntityEventListener> eventListenerGroup =
				configureEventListenerGroup();

		EncryptionMetadata encryptionMetadata = new EncryptionMetadata();
		BDDMockito.when(encryptionMetadataRepository.findAll())
				.thenReturn(Collections.emptyList());
		BDDMockito.when(encryptionMetadataRepository
				.saveAndFlush(BDDMockito.any(EncryptionMetadata.class)))
				.thenReturn(encryptionMetadata);

		keyRotationService.postConstruct();

		BDDMockito.verify(entityManagerFactory).unwrap(SessionFactoryImpl.class);
		BDDMockito.verify(eventListenerGroup).appendListener(encryptionFlushEntityEventListener);
		BDDMockito.verify(keyEncryptionService).keyRotationInProgress();
		BDDMockito.verify(keyEncryptionService, Mockito.times(0)).finishKeyRotation();
		BDDMockito.verify(dataEncryptionKeyRepository, Mockito.times(0)).findAll();
		BDDMockito.verify(dataEncryptionKeyRepository, Mockito.times(0))
				.saveAll(BDDMockito.anyIterable());
		BDDMockito.verify(dataEncryptionKeyRepository, Mockito.times(0)).flush();

		@SuppressWarnings(value = "unchecked")
		Map<Class<?>, Set<String>> annotationsCache = (Map<Class<?>, Set<String>>) getField(
				"annotationsCache", keyRotationService);
		Assertions.assertEquals(1, annotationsCache.size());
		Assertions.assertTrue(
				annotationsCache.get(TestEntity.class).contains(TestConverter.class.getName()));
	}

	@Test
	public void testPostConstruct() {
		KeyRotationService keyRotationService = new KeyRotationService(EncryptionType.ENVIRONMENT,
				false, dataEncryptionKeyRepository, keyEncryptionService,
				encryptionMetadataRepository, webApplicationContext, entityManagerFactory,
				encryptionFlushEntityEventListener);
		EventListenerGroup<FlushEntityEventListener> eventListenerGroup =
				configureEventListenerGroup();
		BDDMockito.when(keyEncryptionService.keyRotationInProgress()).thenReturn(false);

		EncryptionMetadata encryptionMetadata = new EncryptionMetadata();
		BDDMockito.when(encryptionMetadataRepository.findAll())
				.thenReturn(Collections.emptyList());
		BDDMockito.when(encryptionMetadataRepository
				.saveAndFlush(BDDMockito.any(EncryptionMetadata.class)))
				.thenReturn(encryptionMetadata);

		keyRotationService.postConstruct();

		BDDMockito.verify(entityManagerFactory).unwrap(SessionFactoryImpl.class);
		BDDMockito.verify(eventListenerGroup).appendListener(encryptionFlushEntityEventListener);
		BDDMockito.verify(keyEncryptionService).keyRotationInProgress();
		BDDMockito.verify(keyEncryptionService, Mockito.times(0)).finishKeyRotation();
		BDDMockito.verify(dataEncryptionKeyRepository, Mockito.times(0)).findAll();
		BDDMockito.verify(dataEncryptionKeyRepository, Mockito.times(0))
				.saveAll(BDDMockito.anyIterable());
		BDDMockito.verify(dataEncryptionKeyRepository, Mockito.times(0)).flush();

		@SuppressWarnings(value = "unchecked")
		Map<Class<?>, Set<String>> annotationsCache = (Map<Class<?>, Set<String>>) getField(
				"annotationsCache", keyRotationService);
		Assertions.assertEquals(1, annotationsCache.size());
		Assertions.assertTrue(
				annotationsCache.get(TestEntity.class).contains(TestConverter.class.getName()));
	}

	@Test
	public void testPostConstructWithRotation() {
		KeyRotationService keyRotationService = new KeyRotationService(EncryptionType.ENVIRONMENT,
				false, dataEncryptionKeyRepository, keyEncryptionService,
				encryptionMetadataRepository, webApplicationContext, entityManagerFactory,
				encryptionFlushEntityEventListener);
		EventListenerGroup<FlushEntityEventListener> eventListenerGroup =
				configureEventListenerGroup();
		BDDMockito.when(keyEncryptionService.keyRotationInProgress()).thenReturn(true);

		DataEncryptionKey dataEncryptionKey = new DataEncryptionKey();
		dataEncryptionKey.setConverterClassName(TestConverter.class.getName());
		dataEncryptionKey.setCurrentKey(EncryptionUtils.generateKey());
		BDDMockito.when(dataEncryptionKeyRepository.findAll())
				.thenReturn(Collections.singletonList(dataEncryptionKey));

		EncryptionMetadata encryptionMetadata = new EncryptionMetadata();
		encryptionMetadata.setLastRotationDateTime(LocalDateTime.now());
		BDDMockito.when(encryptionMetadataRepository.findAll())
				.thenReturn(Collections.singletonList(encryptionMetadata));

		keyRotationService.postConstruct();

		BDDMockito.verify(entityManagerFactory).unwrap(SessionFactoryImpl.class);
		BDDMockito.verify(eventListenerGroup).appendListener(encryptionFlushEntityEventListener);
		BDDMockito.verify(keyEncryptionService).keyRotationInProgress();
		BDDMockito.verify(keyEncryptionService).finishKeyRotation();
		BDDMockito.verify(dataEncryptionKeyRepository).findAll();

		@SuppressWarnings(value = "unchecked")
		ArgumentCaptor<List<DataEncryptionKey>> captor = ArgumentCaptor.forClass(List.class);
		BDDMockito.verify(dataEncryptionKeyRepository).saveAll(captor.capture());
		BDDMockito.verify(dataEncryptionKeyRepository).flush();

		Assertions.assertEquals(1, captor.getValue().size());
		Assertions.assertEquals(dataEncryptionKey, captor.getValue().get(0));

		BDDMockito.verify(encryptionMetadataRepository, Mockito.times(2)).findAll();
		BDDMockito.verify(encryptionMetadataRepository)
				.saveAndFlush(encryptionMetadata);
		Assertions.assertEquals(LocalDate.now(),
				encryptionMetadata.getLastRotationDateTime().toLocalDate());
	}

	@Test
	public void testPreDestroyEncryptionTypeNone() {
		KeyRotationService keyRotationService = new KeyRotationService(EncryptionType.NONE,
				false, dataEncryptionKeyRepository, keyEncryptionService,
				encryptionMetadataRepository, webApplicationContext, entityManagerFactory,
				encryptionFlushEntityEventListener);
		configureEventListenerGroup();
		BDDMockito.when(keyEncryptionService.keyRotationInProgress()).thenReturn(false);

		EncryptionMetadata encryptionMetadata = new EncryptionMetadata();
		BDDMockito.when(encryptionMetadataRepository.findAll())
				.thenReturn(Collections.emptyList());
		BDDMockito.when(encryptionMetadataRepository
				.saveAndFlush(BDDMockito.any(EncryptionMetadata.class)))
				.thenReturn(encryptionMetadata);

		keyRotationService.postConstruct();

		keyRotationService.preDestroy();
		BDDMockito.verify(dataEncryptionKeyRepository, Mockito.times(0)).deleteAll();
		BDDMockito.verify(encryptionMetadataRepository, Mockito.times(0)).deleteAll();
	}

	@Test
	public void testPreDestroyEncryptionTypeEnvironment() {
		KeyRotationService keyRotationService = new KeyRotationService(EncryptionType.ENVIRONMENT,
				false, dataEncryptionKeyRepository, keyEncryptionService,
				encryptionMetadataRepository, webApplicationContext, entityManagerFactory,
				encryptionFlushEntityEventListener);
		configureEventListenerGroup();
		BDDMockito.when(keyEncryptionService.keyRotationInProgress()).thenReturn(false);

		EncryptionMetadata encryptionMetadata = new EncryptionMetadata();
		BDDMockito.when(encryptionMetadataRepository.findAll())
				.thenReturn(Collections.emptyList());
		BDDMockito.when(encryptionMetadataRepository
				.saveAndFlush(BDDMockito.any(EncryptionMetadata.class)))
				.thenReturn(encryptionMetadata);

		keyRotationService.postConstruct();

		keyRotationService.preDestroy();
		BDDMockito.verify(dataEncryptionKeyRepository, Mockito.times(0)).deleteAll();
		BDDMockito.verify(encryptionMetadataRepository, Mockito.times(0)).deleteAll();
	}

	@Test
	public void testPreDestroyEncryptionTypeEnvironmentDecryptMode() {
		KeyRotationService keyRotationService = new KeyRotationService(EncryptionType.ENVIRONMENT,
				true, dataEncryptionKeyRepository, keyEncryptionService,
				encryptionMetadataRepository, webApplicationContext, entityManagerFactory,
				encryptionFlushEntityEventListener);
		configureEventListenerGroup();
		BDDMockito.when(keyEncryptionService.keyRotationInProgress()).thenReturn(false);

		EncryptionMetadata encryptionMetadata = new EncryptionMetadata();
		BDDMockito.when(encryptionMetadataRepository.findAll())
				.thenReturn(Collections.emptyList());
		BDDMockito.when(encryptionMetadataRepository
				.saveAndFlush(BDDMockito.any(EncryptionMetadata.class)))
				.thenReturn(encryptionMetadata);

		keyRotationService.postConstruct();

		keyRotationService.preDestroy();
		BDDMockito.verify(dataEncryptionKeyRepository).deleteAll();
		BDDMockito.verify(encryptionMetadataRepository).deleteAll();
	}

	@Test
	public void testOnApplicationEventEncryptionTypeNone() {
		KeyRotationService keyRotationService = new KeyRotationService(EncryptionType.NONE,
				false, dataEncryptionKeyRepository, keyEncryptionService,
				encryptionMetadataRepository, webApplicationContext, entityManagerFactory,
				encryptionFlushEntityEventListener);
		configureEventListenerGroup();
		keyRotationService.postConstruct();

		keyRotationService.onApplicationEvent(null);

		BDDMockito.verify(dataEncryptionKeyRepository, Mockito.times(0)).findAll();
		BDDMockito.verify(dataEncryptionKeyRepository, Mockito.times(0))
				.saveAndFlush(BDDMockito.any(DataEncryptionKey.class));
	}

	@Test
	public void testOnApplicationEventEncryptionTypeEnvironmentDecryptionConfigured() {
		KeyRotationService keyRotationService = new KeyRotationService(EncryptionType.ENVIRONMENT,
				true, dataEncryptionKeyRepository, keyEncryptionService,
				encryptionMetadataRepository, webApplicationContext, entityManagerFactory,
				encryptionFlushEntityEventListener);
		configureEventListenerGroup();

		EncryptionMetadata encryptionMetadata = new EncryptionMetadata();
		BDDMockito.when(encryptionMetadataRepository.findAll())
				.thenReturn(Collections.emptyList());
		BDDMockito.when(encryptionMetadataRepository
				.saveAndFlush(BDDMockito.any(EncryptionMetadata.class)))
				.thenReturn(encryptionMetadata);

		keyRotationService.postConstruct();

		BDDMockito.when(dataEncryptionKeyRepository.findAll())
				.thenReturn(Collections.singletonList(dataEncryptionKey));

		keyRotationService.onApplicationEvent(null);

		BDDMockito.verify(dataEncryptionKeyRepository, Mockito.times(2)).findAll();
		BDDMockito.verify(dataEncryptionKeyRepository, Mockito.times(2))
				.saveAndFlush(dataEncryptionKey);
	}

	@Test
	public void testOnApplicationEvent() {
		KeyRotationService keyRotationService = new KeyRotationService(EncryptionType.ENVIRONMENT,
				false, dataEncryptionKeyRepository, keyEncryptionService,
				encryptionMetadataRepository, webApplicationContext, entityManagerFactory,
				encryptionFlushEntityEventListener);
		configureEventListenerGroup();

		EncryptionMetadata encryptionMetadata = new EncryptionMetadata();
		BDDMockito.when(encryptionMetadataRepository.findAll())
				.thenReturn(Collections.emptyList());
		BDDMockito.when(encryptionMetadataRepository
				.saveAndFlush(BDDMockito.any(EncryptionMetadata.class)))
				.thenReturn(encryptionMetadata);

		keyRotationService.postConstruct();

		BDDMockito.when(dataEncryptionKeyRepository
				.findAll()).thenReturn(Collections.singletonList(dataEncryptionKey));
		BDDMockito.when(dataEncryptionKeyRepository
				.findByConverterClassName(TestConverter.class.getName()))
				.thenReturn(Optional.of(dataEncryptionKey));
		dataEncryptionKey.setRotationInProgress(true);
		BDDMockito.when(dataEncryptionKeyRepository
				.saveAndFlush(BDDMockito.any(DataEncryptionKey.class)))
				.thenReturn(dataEncryptionKey);

		keyRotationService.onApplicationEvent(null);

		BDDMockito.verify(dataEncryptionKeyRepository).findAll();
		BDDMockito.verify(dataEncryptionKeyRepository, Mockito.times(3))
				.saveAndFlush(dataEncryptionKey);

		Assertions.assertEquals(TestConverter.class.getName(),
				dataEncryptionKey.getConverterClassName());
		Assertions.assertNotNull(dataEncryptionKey.getCurrentKey());
		Assertions.assertEquals(LocalDate.now(),
				dataEncryptionKey.getLastRotationDateTime().toLocalDate());
		Assertions.assertNull(dataEncryptionKey.getPreviousKey());
		Assertions.assertFalse(dataEncryptionKey.isRotationInProgress());
	}

	@Test
	public void testOnApplicationEventCreateDeks() {
		KeyRotationService keyRotationService = new KeyRotationService(EncryptionType.ENVIRONMENT,
				false, dataEncryptionKeyRepository, keyEncryptionService,
				encryptionMetadataRepository, webApplicationContext, entityManagerFactory,
				encryptionFlushEntityEventListener);
		configureEventListenerGroup();

		EncryptionMetadata encryptionMetadata = new EncryptionMetadata();
		BDDMockito.when(encryptionMetadataRepository.findAll())
				.thenReturn(Collections.emptyList());
		BDDMockito.when(encryptionMetadataRepository
				.saveAndFlush(BDDMockito.any(EncryptionMetadata.class)))
				.thenReturn(encryptionMetadata);

		keyRotationService.postConstruct();

		BDDMockito.when(dataEncryptionKeyRepository
				.findAll()).thenReturn(Collections.emptyList());
		BDDMockito.when(dataEncryptionKeyRepository
				.findByConverterClassName(TestConverter.class.getName()))
				.thenReturn(Optional.empty());
		dataEncryptionKey.setRotationInProgress(true);
		BDDMockito.when(dataEncryptionKeyRepository
				.saveAndFlush(BDDMockito.any(DataEncryptionKey.class)))
				.thenReturn(dataEncryptionKey);

		keyRotationService.onApplicationEvent(null);

		BDDMockito.verify(dataEncryptionKeyRepository).findAll();
		BDDMockito.verify(dataEncryptionKeyRepository, Mockito.times(2))
				.saveAndFlush(BDDMockito.any(DataEncryptionKey.class));

		Assertions.assertEquals(TestConverter.class.getName(),
				dataEncryptionKey.getConverterClassName());
		Assertions.assertNotNull(dataEncryptionKey.getCurrentKey());
		Assertions.assertEquals(LocalDate.now(),
				dataEncryptionKey.getLastRotationDateTime().toLocalDate());
		Assertions.assertNull(dataEncryptionKey.getPreviousKey());
		Assertions.assertFalse(dataEncryptionKey.isRotationInProgress());
	}

	@Test
	public void testGetKeys() {
		KeyRotationService keyRotationService = new KeyRotationService(EncryptionType.ENVIRONMENT,
				false, dataEncryptionKeyRepository, keyEncryptionService,
				encryptionMetadataRepository, webApplicationContext, entityManagerFactory,
				encryptionFlushEntityEventListener);
		configureEventListenerGroup();

		EncryptionMetadata encryptionMetadata = new EncryptionMetadata();
		BDDMockito.when(encryptionMetadataRepository.findAll())
				.thenReturn(Collections.emptyList());
		BDDMockito.when(encryptionMetadataRepository
				.saveAndFlush(BDDMockito.any(EncryptionMetadata.class)))
				.thenReturn(encryptionMetadata);

		keyRotationService.postConstruct();

		dataEncryptionKey = new DataEncryptionKey();
		BDDMockito.when(dataEncryptionKeyRepository.findAll())
				.thenReturn(Collections.singletonList(dataEncryptionKey));
		List<DataEncryptionKey> keys = keyRotationService.getKeys();
		Assertions.assertEquals(1, keys.size());
		Assertions.assertEquals(dataEncryptionKey, keys.get(0));
	}

	@Test
	public void testRotateKeysInProgress() {
		KeyRotationService keyRotationService = new KeyRotationService(EncryptionType.ENVIRONMENT,
				false, dataEncryptionKeyRepository, keyEncryptionService,
				encryptionMetadataRepository, webApplicationContext, entityManagerFactory,
				encryptionFlushEntityEventListener);
		configureEventListenerGroup();

		EncryptionMetadata encryptionMetadata = new EncryptionMetadata();
		BDDMockito.when(encryptionMetadataRepository.findAll())
				.thenReturn(Collections.emptyList());
		BDDMockito.when(encryptionMetadataRepository
				.saveAndFlush(BDDMockito.any(EncryptionMetadata.class)))
				.thenReturn(encryptionMetadata);

		keyRotationService.postConstruct();

		dataEncryptionKey = new DataEncryptionKey();
		dataEncryptionKey.setConverterClassName(TestConverter.class.getName());
		dataEncryptionKey.setRotationInProgress(true);
		BDDMockito.when(dataEncryptionKeyRepository.findAll())
				.thenReturn(Collections.singletonList(dataEncryptionKey));

		keyRotationService.rotateKeys();

		BDDMockito.verify(dataEncryptionKeyRepository, Mockito.times(0))
				.saveAll(BDDMockito.anyIterable());

		Assertions.assertFalse(logWatcher.getMessages().isEmpty());
		Assertions.assertEquals("Skipping key rotation for converter " + dataEncryptionKey
				.getConverterClassName(), logWatcher.getMessages().get(0));
	}

	@Test
	public void testRotateKeys() {
		KeyRotationService keyRotationService = new KeyRotationService(EncryptionType.ENVIRONMENT,
				false, dataEncryptionKeyRepository, keyEncryptionService,
				encryptionMetadataRepository, webApplicationContext, entityManagerFactory,
				encryptionFlushEntityEventListener);
		configureEventListenerGroup();

		EncryptionMetadata encryptionMetadata = new EncryptionMetadata();
		BDDMockito.when(encryptionMetadataRepository.findAll())
				.thenReturn(Collections.emptyList());
		BDDMockito.when(encryptionMetadataRepository
				.saveAndFlush(BDDMockito.any(EncryptionMetadata.class)))
				.thenReturn(encryptionMetadata);

		keyRotationService.postConstruct();

		dataEncryptionKey = new DataEncryptionKey();
		dataEncryptionKey.setConverterClassName(TestConverter.class.getName());
		Key key = EncryptionUtils.generateKey();
		dataEncryptionKey.setCurrentKey(key);
		BDDMockito.when(dataEncryptionKeyRepository.findAll())
				.thenReturn(Collections.singletonList(dataEncryptionKey));

		TestEntity testEntity = new TestEntity();
		TestRepository repository = BDDMockito.mock(TestRepository.class);
		BDDMockito.when(repository.findAll(BDDMockito.any(PageRequest.class)))
				.thenReturn(new PageImpl<>(Collections.singletonList(testEntity)));
		BDDMockito.when(webApplicationContext.getBean(TestRepository.class.getName()))
				.thenReturn(repository);

		keyRotationService.rotateKeys();

		BDDMockito.verify(dataEncryptionKeyRepository, Mockito.times(2))
				.saveAndFlush(dataEncryptionKey);
		@SuppressWarnings(value = "unchecked")
		ArgumentCaptor<List<TestEntity>> captor = ArgumentCaptor.forClass(List.class);
		BDDMockito.verify(repository).saveAll(captor.capture());
		Assertions.assertFalse(captor.getValue().isEmpty());
		Assertions.assertEquals(testEntity, captor.getValue().get(0));

		Assertions.assertEquals(key, dataEncryptionKey.getPreviousKey());
		Assertions.assertEquals(LocalDate.now(),
				dataEncryptionKey.getLastRotationDateTime().toLocalDate());
		Assertions.assertFalse(dataEncryptionKey.isRotationInProgress());
		Assertions.assertFalse(logWatcher.getMessages().isEmpty());
		Assertions.assertEquals(
				"Starting data encryption key rotation for converter " + dataEncryptionKey
						.getConverterClassName(),
				logWatcher.getMessages().get(0));
		Assertions.assertEquals(
				"Finished data encryption key rotation for converter " + dataEncryptionKey
						.getConverterClassName(),
				logWatcher.getMessages().get(1));
	}

	@Test
	public void testRotateKeyInvalidId() {
		KeyRotationService keyRotationService = new KeyRotationService(EncryptionType.ENVIRONMENT,
				false, dataEncryptionKeyRepository, keyEncryptionService,
				encryptionMetadataRepository, webApplicationContext, entityManagerFactory,
				encryptionFlushEntityEventListener);
		configureEventListenerGroup();

		EncryptionMetadata encryptionMetadata = new EncryptionMetadata();
		BDDMockito.when(encryptionMetadataRepository.findAll())
				.thenReturn(Collections.emptyList());
		BDDMockito.when(encryptionMetadataRepository
				.saveAndFlush(BDDMockito.any(EncryptionMetadata.class)))
				.thenReturn(encryptionMetadata);

		keyRotationService.postConstruct();

		BDDMockito.when(dataEncryptionKeyRepository.findById(1L)).thenReturn(Optional.empty());

		keyRotationService.rotateKey(1L);

		BDDMockito.verify(dataEncryptionKeyRepository, Mockito.times(0))
				.saveAll(BDDMockito.anyIterable());

		Assertions.assertFalse(logWatcher.getMessages().isEmpty());
		Assertions.assertEquals(
				"Skipping key rotation: no data encryption key found with the given id",
				logWatcher.getMessages().get(0));
	}

	@Test
	public void testRotateKeyInProgress() {
		KeyRotationService keyRotationService = new KeyRotationService(EncryptionType.ENVIRONMENT,
				false, dataEncryptionKeyRepository, keyEncryptionService,
				encryptionMetadataRepository, webApplicationContext, entityManagerFactory,
				encryptionFlushEntityEventListener);
		configureEventListenerGroup();

		EncryptionMetadata encryptionMetadata = new EncryptionMetadata();
		BDDMockito.when(encryptionMetadataRepository.findAll())
				.thenReturn(Collections.emptyList());
		BDDMockito.when(encryptionMetadataRepository
				.saveAndFlush(BDDMockito.any(EncryptionMetadata.class)))
				.thenReturn(encryptionMetadata);

		keyRotationService.postConstruct();

		dataEncryptionKey = new DataEncryptionKey();
		dataEncryptionKey.setConverterClassName(TestConverter.class.getName());
		dataEncryptionKey.setRotationInProgress(true);
		BDDMockito.when(dataEncryptionKeyRepository.findById(1L))
				.thenReturn(Optional.of(dataEncryptionKey));

		keyRotationService.rotateKey(1L);

		BDDMockito.verify(dataEncryptionKeyRepository, Mockito.times(0))
				.saveAll(BDDMockito.anyIterable());

		Assertions.assertFalse(logWatcher.getMessages().isEmpty());
		Assertions.assertEquals("Skipping key rotation for converter " + dataEncryptionKey
				.getConverterClassName(), logWatcher.getMessages().get(0));
	}

	@Test
	public void testRotateKey() {
		KeyRotationService keyRotationService = new KeyRotationService(EncryptionType.ENVIRONMENT,
				false, dataEncryptionKeyRepository, keyEncryptionService,
				encryptionMetadataRepository, webApplicationContext, entityManagerFactory,
				encryptionFlushEntityEventListener);
		configureEventListenerGroup();

		EncryptionMetadata encryptionMetadata = new EncryptionMetadata();
		BDDMockito.when(encryptionMetadataRepository.findAll())
				.thenReturn(Collections.emptyList());
		BDDMockito.when(encryptionMetadataRepository
				.saveAndFlush(BDDMockito.any(EncryptionMetadata.class)))
				.thenReturn(encryptionMetadata);

		keyRotationService.postConstruct();

		dataEncryptionKey = new DataEncryptionKey();
		dataEncryptionKey.setConverterClassName(TestConverter.class.getName());
		Key key = EncryptionUtils.generateKey();
		dataEncryptionKey.setCurrentKey(key);
		BDDMockito.when(dataEncryptionKeyRepository.findById(1L))
				.thenReturn(Optional.of(dataEncryptionKey));

		TestEntity testEntity1 = new TestEntity();
		Pageable pageable1 = PageRequest.of(0, 50);
		@SuppressWarnings(value = "unchecked")
		Page<TestEntity> page1 = BDDMockito.mock(PageImpl.class);
		BDDMockito.when(page1.hasNext()).thenReturn(true);
		BDDMockito.when(page1.getContent()).thenReturn(Collections.singletonList(testEntity1));
		TestEntity testEntity2 = new TestEntity();
		@SuppressWarnings(value = "unchecked")
		Page<TestEntity> page2 = BDDMockito.mock(PageImpl.class);
		BDDMockito.when(page2.hasNext()).thenReturn(false);
		BDDMockito.when(page2.getContent()).thenReturn(Collections.singletonList(testEntity2));

		TestRepository repository = BDDMockito.mock(TestRepository.class);
		BDDMockito.when(repository.findAll(pageable1)).thenReturn(page1);
		BDDMockito.when(repository.findAll(pageable1.next())).thenReturn(page2);
		BDDMockito.when(webApplicationContext.getBean(TestRepository.class.getName()))
				.thenReturn(repository);

		keyRotationService.rotateKey(1L);

		@SuppressWarnings(value = "unchecked")
		ArgumentCaptor<List<TestEntity>> captor = ArgumentCaptor.forClass(List.class);
		BDDMockito.verify(repository, Mockito.times(2)).saveAll(captor.capture());
		List<List<TestEntity>> captorLists = captor.getAllValues();
		Assertions.assertEquals(2, captorLists.size());
		Assertions.assertEquals(1, captorLists.get(0).size());
		Assertions.assertEquals(testEntity1, captorLists.get(0).get(0));
		Assertions.assertEquals(1, captorLists.get(1).size());
		Assertions.assertEquals(testEntity2, captorLists.get(1).get(0));

		BDDMockito.verify(dataEncryptionKeyRepository, Mockito.times(2))
				.saveAndFlush(dataEncryptionKey);
		Assertions.assertEquals(key, dataEncryptionKey.getPreviousKey());
		Assertions.assertEquals(LocalDate.now(),
				dataEncryptionKey.getLastRotationDateTime().toLocalDate());
		Assertions.assertFalse(dataEncryptionKey.isRotationInProgress());
		Assertions.assertFalse(logWatcher.getMessages().isEmpty());
		Assertions.assertEquals(
				"Starting data encryption key rotation for converter " + dataEncryptionKey
						.getConverterClassName(),
				logWatcher.getMessages().get(0));
		Assertions.assertEquals(
				"Finished data encryption key rotation for converter " + dataEncryptionKey
						.getConverterClassName(),
				logWatcher.getMessages().get(1));
	}

	@Test
	public void testEnableRotationScheduleNullPeriod() {
		KeyRotationService keyRotationService = new KeyRotationService(EncryptionType.ENVIRONMENT,
				false, dataEncryptionKeyRepository, keyEncryptionService,
				encryptionMetadataRepository, webApplicationContext, entityManagerFactory,
				encryptionFlushEntityEventListener);
		configureEventListenerGroup();

		EncryptionMetadata encryptionMetadata = new EncryptionMetadata();
		BDDMockito.when(encryptionMetadataRepository.findAll())
				.thenReturn(Collections.emptyList());
		BDDMockito.when(encryptionMetadataRepository
				.saveAndFlush(BDDMockito.any(EncryptionMetadata.class)))
				.thenReturn(encryptionMetadata);

		keyRotationService.postConstruct();

		try {
			keyRotationService.enableRotationSchedule(true, null);
			Assertions.fail("Should have thrown exception");
		} catch (IllegalArgumentException e) {
			Assertions.assertEquals(
					"Please provide a rotation period greater than zero to enable scheduled rotations",
					e.getMessage());
		}
	}

	@Test
	public void testEnableRotationScheduleNegativePeriod() {
		KeyRotationService keyRotationService = new KeyRotationService(EncryptionType.ENVIRONMENT,
				false, dataEncryptionKeyRepository, keyEncryptionService,
				encryptionMetadataRepository, webApplicationContext, entityManagerFactory,
				encryptionFlushEntityEventListener);
		configureEventListenerGroup();

		EncryptionMetadata encryptionMetadata = new EncryptionMetadata();
		BDDMockito.when(encryptionMetadataRepository.findAll())
				.thenReturn(Collections.emptyList());
		BDDMockito.when(encryptionMetadataRepository
				.saveAndFlush(BDDMockito.any(EncryptionMetadata.class)))
				.thenReturn(encryptionMetadata);

		keyRotationService.postConstruct();

		try {
			keyRotationService.enableRotationSchedule(true, -1);
			Assertions.fail("Should have thrown exception");
		} catch (IllegalArgumentException e) {
			Assertions.assertEquals(
					"Please provide a rotation period greater than zero to enable scheduled rotations",
					e.getMessage());
		}
	}

	@Test
	public void testEnableRotationSchedule() {
		KeyRotationService keyRotationService = new KeyRotationService(EncryptionType.ENVIRONMENT,
				false, dataEncryptionKeyRepository, keyEncryptionService,
				encryptionMetadataRepository, webApplicationContext, entityManagerFactory,
				encryptionFlushEntityEventListener);
		configureEventListenerGroup();

		EncryptionMetadata encryptionMetadata = new EncryptionMetadata();
		encryptionMetadata.setLastRotationDateTime(LocalDateTime.now());
		BDDMockito.when(encryptionMetadataRepository.findAll())
				.thenReturn(Collections.singletonList(encryptionMetadata));

		keyRotationService.postConstruct();

		Assertions.assertFalse(encryptionMetadata.isRotationScheduleEnabled());

		keyRotationService.enableRotationSchedule(true, 90);

		BDDMockito.verify(encryptionMetadataRepository).saveAndFlush(encryptionMetadata);
		Assertions.assertTrue(encryptionMetadata.isRotationScheduleEnabled());
		Assertions.assertEquals(90, encryptionMetadata.getRotationPeriod(), 0.001);
	}

	@Test
	public void testEnableRotationScheduleDisable() {
		KeyRotationService keyRotationService = new KeyRotationService(EncryptionType.ENVIRONMENT,
				false, dataEncryptionKeyRepository, keyEncryptionService,
				encryptionMetadataRepository, webApplicationContext, entityManagerFactory,
				encryptionFlushEntityEventListener);
		configureEventListenerGroup();

		EncryptionMetadata encryptionMetadata = new EncryptionMetadata();
		encryptionMetadata.setLastRotationDateTime(LocalDateTime.now());
		encryptionMetadata.setRotationScheduleEnabled(true);
		BDDMockito.when(encryptionMetadataRepository.findAll())
				.thenReturn(Collections.singletonList(encryptionMetadata));

		keyRotationService.postConstruct();

		Assertions.assertTrue(encryptionMetadata.isRotationScheduleEnabled());
		keyRotationService.enableRotationSchedule(false, 90);

		BDDMockito.verify(encryptionMetadataRepository).saveAndFlush(encryptionMetadata);
		Assertions.assertFalse(encryptionMetadata.isRotationScheduleEnabled());
		Assertions.assertNull(encryptionMetadata.getRotationPeriod());
	}

	@Test
	public void testAutoRotateKeysNotEnabled() throws Exception {
		KeyRotationService keyRotationService = new KeyRotationService(EncryptionType.ENVIRONMENT,
				false, dataEncryptionKeyRepository, keyEncryptionService,
				encryptionMetadataRepository, webApplicationContext, entityManagerFactory,
				encryptionFlushEntityEventListener);
		configureEventListenerGroup();

		EncryptionMetadata encryptionMetadata = new EncryptionMetadata();
		BDDMockito.when(encryptionMetadataRepository.findAll())
				.thenReturn(Collections.singletonList(encryptionMetadata));

		keyRotationService.postConstruct();

		Method autoRotateMethod = getMethod("autoRotateKeys", KeyRotationService.class);
		ReflectionUtils.makeAccessible(autoRotateMethod);

		autoRotateMethod.invoke(keyRotationService);
		Assertions.assertEquals(1, logWatcher.getMessages().size());
		Assertions.assertEquals("Auto-rotation not configured", logWatcher.getMessages().get(0));

		BDDMockito.verify(dataEncryptionKeyRepository, Mockito.times(0)).findAll();
	}

	@Test
	public void testAutoRotateKeysNoPeriodConfigured() throws Exception {
		KeyRotationService keyRotationService = new KeyRotationService(EncryptionType.ENVIRONMENT,
				false, dataEncryptionKeyRepository, keyEncryptionService,
				encryptionMetadataRepository, webApplicationContext, entityManagerFactory,
				encryptionFlushEntityEventListener);
		configureEventListenerGroup();

		EncryptionMetadata encryptionMetadata = new EncryptionMetadata();
		encryptionMetadata.setRotationScheduleEnabled(true);
		BDDMockito.when(encryptionMetadataRepository.findAll())
				.thenReturn(Collections.singletonList(encryptionMetadata));

		keyRotationService.postConstruct();

		Method autoRotateMethod = getMethod("autoRotateKeys", KeyRotationService.class);
		ReflectionUtils.makeAccessible(autoRotateMethod);

		autoRotateMethod.invoke(keyRotationService);
		Assertions.assertEquals(1, logWatcher.getMessages().size());
		Assertions.assertEquals("Auto-rotation not configured", logWatcher.getMessages().get(0));

		BDDMockito.verify(dataEncryptionKeyRepository, Mockito.times(0)).findAll();
	}

	@Test
	public void testAutoRotateKeys() throws Exception {
		KeyRotationService keyRotationService = new KeyRotationService(EncryptionType.ENVIRONMENT,
				false, dataEncryptionKeyRepository, keyEncryptionService,
				encryptionMetadataRepository, webApplicationContext, entityManagerFactory,
				encryptionFlushEntityEventListener);
		configureEventListenerGroup();

		EncryptionMetadata encryptionMetadata = new EncryptionMetadata();
		encryptionMetadata.setRotationScheduleEnabled(true);
		encryptionMetadata.setRotationPeriod(90);
		BDDMockito.when(encryptionMetadataRepository.findAll())
				.thenReturn(Collections.singletonList(encryptionMetadata));

		keyRotationService.postConstruct();

		DataEncryptionKey key1 = new DataEncryptionKey();
		DataEncryptionKey key2 = new DataEncryptionKey();
		key2.setLastRotationDateTime(LocalDateTime.now().minusDays(40));
		DataEncryptionKey key3 = new DataEncryptionKey();
		key3.setConverterClassName(TestConverter.class.getName());
		key3.setCurrentKey(EncryptionUtils.generateKey());
		key3.setLastRotationDateTime(LocalDateTime.now().minusDays(100));
		BDDMockito.when(dataEncryptionKeyRepository.findAll())
				.thenReturn(Arrays.asList(key1, key2, key3));

		Method autoRotateMethod = getMethod("autoRotateKeys", KeyRotationService.class);
		ReflectionUtils.makeAccessible(autoRotateMethod);

		autoRotateMethod.invoke(keyRotationService);

		Assertions.assertEquals(3, logWatcher.getMessages().size());
		Assertions.assertEquals("Starting data encryption key rotation for converter " + key3
				.getConverterClassName(), logWatcher.getMessages().get(0));
		Assertions.assertEquals("Found entity class " + TestEntity.class.getName()
				+ " with @Convert annotation but cannot get associated repository.",
				logWatcher.getMessages().get(1));
		Assertions.assertEquals("Finished data encryption key rotation for converter " + key3
				.getConverterClassName(), logWatcher.getMessages().get(2));

		BDDMockito.verify(dataEncryptionKeyRepository).findAll();
	}

	private EventListenerGroup<FlushEntityEventListener> configureEventListenerGroup() {
		@SuppressWarnings(value = "unchecked")
		EventListenerGroup<FlushEntityEventListener> eventListenerGroup = BDDMockito
				.mock(EventListenerGroup.class);
		EventListenerRegistry registry = BDDMockito.mock(EventListenerRegistry.class);
		ServiceRegistryImplementor serviceRegistry = BDDMockito
				.mock(ServiceRegistryImplementor.class);
		SessionFactoryImpl sessionFactory = BDDMockito.mock(SessionFactoryImpl.class);
		BDDMockito.when(sessionFactory.getServiceRegistry()).thenReturn(serviceRegistry);
		BDDMockito.when(serviceRegistry.getService(EventListenerRegistry.class))
				.thenReturn(registry);
		BDDMockito.when(registry.getEventListenerGroup(EventType.FLUSH_ENTITY))
				.thenReturn(eventListenerGroup);
		BDDMockito.when(entityManagerFactory.unwrap(SessionFactoryImpl.class))
				.thenReturn(sessionFactory);
		return eventListenerGroup;
	}

	private static Object getField(String name, Object target) {
		Field field = ReflectionUtils
				.findField(KeyRotationService.class, name);
		if (field == null) {
			Assertions.fail("Cannot find " + name + " field");
		}
		ReflectionUtils.makeAccessible(field);
		return ReflectionUtils.getField(field, target);
	}

	private static Method getMethod(String name, Class<?> target) {
		Optional<Method> autoRotateMethod = Arrays
				.stream(ReflectionUtils.getAllDeclaredMethods(target))
				.filter(m -> m.getName().equals(name)).findFirst();
		if (!autoRotateMethod.isPresent()) {
			Assertions.fail("Cannot find " + name + " method");
		}
		return autoRotateMethod.get();
	}

	static class TestRepositoryInformation implements RepositoryInformation {

		@Override
		public Class<?> getRepositoryBaseClass() {
			return SimpleJpaRepository.class;
		}

		@Override
		public boolean hasCustomMethod() {
			return false;
		}

		@Override
		public boolean isCustomMethod(Method method) {
			return false;
		}

		@Override
		public boolean isQueryMethod(Method method) {
			return false;
		}

		@Override
		public boolean isBaseClassMethod(Method method) {
			return false;
		}

		@Override
		public Streamable<Method> getQueryMethods() {
			return null;
		}

		@Override
		public Method getTargetClassMethod(Method method) {
			return null;
		}

		@Override
		public Class<?> getIdType() {
			return Long.class;
		}

		@Override
		public Class<?> getDomainType() {
			return TestEntity.class;
		}

		@Override
		public Class<?> getRepositoryInterface() {
			return TestRepository.class;
		}

		@Override
		public Class<?> getReturnedDomainClass(Method method) {
			return null;
		}

		@Override
		public CrudMethods getCrudMethods() {
			return null;
		}

		@Override
		public boolean isPagingRepository() {
			return false;
		}

		@Override
		public Set<Class<?>> getAlternativeDomainTypes() {
			return new HashSet<>();
		}

		@Override
		public boolean isReactiveRepository() {
			return false;
		}

		@Override
		public TypeInformation<?> getReturnType(Method method) {
			return null;
		}
	}

	interface TestRepository extends JpaRepository<TestEntity, Long> {

	}

	static class TestEntityInformation implements EntityInformation<TestEntity, Long> {

		@Override
		public boolean isNew(TestEntity testEntity) {
			return false;
		}

		@Override
		public Long getId(TestEntity testEntity) {
			return testEntity.getId();
		}

		@Override
		public Class<Long> getIdType() {
			return Long.class;
		}

		@Override
		public Class<TestEntity> getJavaType() {
			return TestEntity.class;
		}
	}

	static class TestEntity {

		private Long id = 1L;

		@Convert(converter = TestConverter.class)
		private String secret = "foo";

		public Long getId() {
			return id;
		}

		public void setId(Long id) {
			this.id = id;
		}

		public String getSecret() {
			return secret;
		}

		public void setSecret(String secret) {
			this.secret = secret;
		}
	}

	static class TestConverter extends StringEncryptedAttributeConverter {

		public TestConverter(
				@Lazy DataEncryptionService dataEncryptionService) {
			super(dataEncryptionService);
		}
	}
}
