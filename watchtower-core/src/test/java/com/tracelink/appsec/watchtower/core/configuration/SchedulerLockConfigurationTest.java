package com.tracelink.appsec.watchtower.core.configuration;

import java.time.Duration;
import java.time.Instant;
import java.util.Optional;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import com.tracelink.appsec.watchtower.core.WatchtowerTestApplication;
import com.tracelink.appsec.watchtower.core.encryption.service.KeyRotationService;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.service.PullRequestSynchronizer;

import net.javacrumbs.shedlock.core.LockConfiguration;
import net.javacrumbs.shedlock.core.LockProvider;
import net.javacrumbs.shedlock.core.SimpleLock;
import net.javacrumbs.shedlock.spring.annotation.SchedulerLock;

@ExtendWith(SpringExtension.class)
@SpringBootTest(classes = WatchtowerTestApplication.class)
public class SchedulerLockConfigurationTest {

	@Autowired
	private LockProvider lockProvider;

	private Optional<SimpleLock> lock(String name) {
		return lockProvider.lock(new LockConfiguration(Instant.now(), name,
				Duration.ofMinutes(1), Duration.ZERO));
	}

	@Test
	public void secondHolderIsRefusedUntilTheLockIsReleased() {
		Optional<SimpleLock> first = lock("scheduler-lock-test");
		Assertions.assertTrue(first.isPresent());
		Assertions.assertTrue(lock("scheduler-lock-test").isEmpty());

		first.get().unlock();

		Optional<SimpleLock> again = lock("scheduler-lock-test");
		Assertions.assertTrue(again.isPresent());
		again.get().unlock();
	}

	@Test
	public void existingSchedulesRunOnOnePodOnly() throws NoSuchMethodException {
		Assertions.assertEquals("pr-sync", PullRequestSynchronizer.class
				.getMethod("syncData").getAnnotation(SchedulerLock.class).name());
		Assertions.assertEquals("key-rotation", KeyRotationService.class
				.getDeclaredMethod("autoRotateKeys").getAnnotation(SchedulerLock.class).name());
	}
}
