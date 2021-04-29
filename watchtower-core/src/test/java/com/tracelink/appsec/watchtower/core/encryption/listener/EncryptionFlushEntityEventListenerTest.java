package com.tracelink.appsec.watchtower.core.encryption.listener;

import java.security.Key;
import java.util.Optional;

import javax.persistence.Convert;

import org.hibernate.CustomEntityDirtinessStrategy;
import org.hibernate.EmptyInterceptor;
import org.hibernate.engine.spi.EntityEntry;
import org.hibernate.engine.spi.SessionEventListenerManager;
import org.hibernate.engine.spi.SessionFactoryImplementor;
import org.hibernate.event.spi.EventSource;
import org.hibernate.event.spi.FlushEntityEvent;
import org.hibernate.persister.entity.EntityPersister;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.mockito.BDDMockito;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Lazy;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import com.tracelink.appsec.watchtower.core.encryption.converter.DataEncryptionKeyConverter;
import com.tracelink.appsec.watchtower.core.encryption.converter.StringEncryptedAttributeConverter;
import com.tracelink.appsec.watchtower.core.encryption.model.DataEncryptionKey;
import com.tracelink.appsec.watchtower.core.encryption.repository.DataEncryptionKeyRepository;
import com.tracelink.appsec.watchtower.core.encryption.service.DataEncryptionService;
import com.tracelink.appsec.watchtower.core.encryption.service.KeyEncryptionService;
import com.tracelink.appsec.watchtower.core.encryption.utils.EncryptionUtils;
import com.tracelink.appsec.watchtower.core.logging.CoreLogWatchExtension;

import ch.qos.logback.classic.Level;

@ExtendWith(SpringExtension.class)
public class EncryptionFlushEntityEventListenerTest {

	@RegisterExtension
	public final CoreLogWatchExtension logWatcher = CoreLogWatchExtension
			.forClass(EncryptionFlushEntityEventListener.class);

	@MockBean
	private DataEncryptionKeyRepository dataEncryptionKeyRepository;

	@MockBean
	private KeyEncryptionService keyEncryptionService;

	private EncryptionFlushEntityEventListener listener;
	private FlushEntityEvent event;

	@Test
	public void testDirtyCheckSuperNullRotationNotInProgress() {
		TestEntity entity = new TestEntity();
		setupMocks(entity, entity.getKey(), null, "key");

		DataEncryptionKey dataEncryptionKey = new DataEncryptionKey();
		BDDMockito.when(dataEncryptionKeyRepository
				.findByConverterClassName(TestConverter.class.getName())).thenReturn(
						Optional.of(dataEncryptionKey));

		listener.dirtyCheck(event);
		Assertions.assertNull(event.getDirtyProperties());
		Assertions.assertTrue(logWatcher.getMessages().isEmpty());
	}

	@Test
	public void testDirtyCheckSuperNullRotationInProgress() {
		TestEntity entity = new TestEntity();
		setupMocks(entity, entity.getSecret(), null, "secret");

		DataEncryptionKey dataEncryptionKey = new DataEncryptionKey();
		dataEncryptionKey.setRotationInProgress(true);
		BDDMockito.when(dataEncryptionKeyRepository
				.findByConverterClassName(TestConverter.class.getName())).thenReturn(
						Optional.of(dataEncryptionKey));

		listener.dirtyCheck(event);
		Assertions.assertArrayEquals(new int[]{0}, event.getDirtyProperties());
		Assertions.assertEquals(1, logWatcher.getMessages().size());
		Assertions.assertEquals("TestEntity.secret is dirty", logWatcher.getMessages().get(0));
	}

	@Test
	public void testDirtyCheckSuperNullKeyEncryptionKeyRotationInProgress() {
		TestEntity entity = new TestEntity();
		setupMocks(entity, entity.getKey(), null, "key");

		BDDMockito.when(keyEncryptionService.keyRotationInProgress()).thenReturn(true);

		listener.dirtyCheck(event);
		Assertions.assertArrayEquals(new int[]{0}, event.getDirtyProperties());
		Assertions.assertEquals(1, logWatcher.getMessages().size());
		Assertions.assertEquals("TestEntity.key is dirty", logWatcher.getMessages().get(0));
	}

	@Test
	public void testDirtyCheckSuperNullInvalidPropertyName() {
		TestEntity entity = new TestEntity();
		setupMocks(entity, entity.getSecret(), null, "invalid");

		listener.dirtyCheck(event);
		Assertions.assertNull(event.getDirtyProperties());
		Assertions.assertEquals(1, logWatcher.getMessages().size());
		Assertions.assertEquals("Unable to find field TestEntity.invalid",
				logWatcher.getMessages().get(0));
	}

	@Test
	public void testDirtyCheckSuperNotNull() {
		TestEntity entity = new TestEntity();
		setupMocks(entity, entity.getSecret(), new int[]{0}, "secret");

		listener.dirtyCheck(event);
		Assertions.assertArrayEquals(new int[]{0}, event.getDirtyProperties());
		Assertions.assertTrue(logWatcher.getMessages().isEmpty());
	}

	private void setupMocks(TestEntity entity, Object value, int[] superResult,
			String propertyName) {
		logWatcher.withLevel(Level.ALL);
		listener = new EncryptionFlushEntityEventListener(dataEncryptionKeyRepository,
				keyEncryptionService);

		EventSource eventSource = BDDMockito.mock(EventSource.class);
		SessionFactoryImplementor sessionFactoryImplementor = BDDMockito
				.mock(SessionFactoryImplementor.class);
		CustomEntityDirtinessStrategy strategy = BDDMockito
				.mock(CustomEntityDirtinessStrategy.class);
		SessionEventListenerManager listenerManager = BDDMockito
				.mock(SessionEventListenerManager.class);
		EntityEntry entry = BDDMockito.mock(EntityEntry.class);
		EntityPersister persister = BDDMockito.mock(EntityPersister.class);
		event = new FlushEntityEvent(eventSource, entity, entry);
		event.setPropertyValues(new Object[]{value});

		BDDMockito.when(entry.getPersister()).thenReturn(persister);
		BDDMockito.when(entry.getId()).thenReturn(1L);
		BDDMockito.when(entry.getLoadedState()).thenReturn(new Object[]{value});
		BDDMockito.when(entry.getEntityName())
				.thenReturn(TestEntity.class.getSimpleName());
		BDDMockito.when(eventSource.getInterceptor()).thenReturn(EmptyInterceptor.INSTANCE);
		BDDMockito.when(eventSource.getFactory()).thenReturn(sessionFactoryImplementor);
		BDDMockito.when(sessionFactoryImplementor.getCustomEntityDirtinessStrategy())
				.thenReturn(strategy);
		BDDMockito.when(eventSource.getEventListenerManager()).thenReturn(listenerManager);
		BDDMockito.when(persister
				.findDirty(BDDMockito.any(), BDDMockito.any(), BDDMockito.any(), BDDMockito.any()))
				.thenReturn(superResult);
		BDDMockito.when(persister.getPropertyNames()).thenReturn(new String[]{propertyName});
	}

	static class TestEntity {

		private Long id = 1L;

		@Convert(converter = EncryptionFlushEntityEventListenerTest.TestConverter.class)
		private String secret = "foo";

		@Convert(converter = DataEncryptionKeyConverter.class)
		private Key key = EncryptionUtils.generateKey();

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

		public Key getKey() {
			return key;
		}

		public void setKey(Key key) {
			this.key = key;
		}
	}

	static class TestConverter extends StringEncryptedAttributeConverter {

		public TestConverter(
				@Lazy DataEncryptionService dataEncryptionService) {
			super(dataEncryptionService);
		}
	}
}
