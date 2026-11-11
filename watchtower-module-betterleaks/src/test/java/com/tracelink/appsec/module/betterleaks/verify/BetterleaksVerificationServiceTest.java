package com.tracelink.appsec.module.betterleaks.verify;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import org.hamcrest.MatcherAssert;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.BDDMockito;
import org.springframework.dao.DataIntegrityViolationException;

import com.tracelink.appsec.module.betterleaks.BetterleaksModule;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.entity.PullRequestScanEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.entity.PullRequestViolationEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.repository.PRViolationRepository;
import com.tracelink.appsec.watchtower.core.verification.LiveVerificationStatus;

public class BetterleaksVerificationServiceTest {

	private static final Instant NOW = Instant.parse("2026-09-25T12:00:00Z");

	private static final long HOUR = 3_600_000L;

	private static final long SCAN = 77L;

	private static final int BUDGET = 5;

	private BetterleaksVerificationRepository repository;

	private PRViolationRepository violations;

	private BetterleaksVerificationService service;

	@BeforeEach
	public void setup() {
		repository = BDDMockito.mock(BetterleaksVerificationRepository.class);
		violations = BDDMockito.mock(PRViolationRepository.class);
		BDDMockito.when(repository.save(BDDMockito.any()))
				.thenAnswer(invocation -> invocation.getArgument(0));
		service = new BetterleaksVerificationService(repository, violations,
				new VerifiableRules("github-pat", Set.of("github-pat", "gitlab-pat")), BUDGET,
				Clock.fixed(NOW, ZoneOffset.UTC));
	}

	private void givenViolation(long id, String ruleName) {
		PullRequestScanEntity scan = BDDMockito.mock(PullRequestScanEntity.class);
		BDDMockito.when(scan.getId()).thenReturn(SCAN);
		PullRequestViolationEntity violation = BDDMockito.mock(PullRequestViolationEntity.class);
		BDDMockito.when(violation.getViolationName()).thenReturn(ruleName);
		BDDMockito.when(violation.getScan()).thenReturn(scan);
		BDDMockito.when(violations.findById(id)).thenReturn(Optional.of(violation));
	}

	private BetterleaksVerificationEntity saved() {
		ArgumentCaptor<BetterleaksVerificationEntity> captor =
				ArgumentCaptor.forClass(BetterleaksVerificationEntity.class);
		BDDMockito.verify(repository).save(captor.capture());
		return captor.getValue();
	}

	@Test
	public void testSupportsOnlyAllowedBetterleaksRulesAndNeedsItsPrivilege() {
		Assertions.assertTrue(service.supports("Betterleaks: github-pat"));
		// Has a provider check, but security did not allow it.
		Assertions.assertFalse(service.supports("Betterleaks: gitlab-pat"));
		Assertions.assertFalse(service.supports("Betterleaks: custom-internal-token"));
		Assertions.assertFalse(service.supports("Regex: AWS key"));
		Assertions.assertFalse(service.supports(null));
		Assertions.assertEquals(BetterleaksModule.VERIFY_PRIVILEGE_NAME,
				service.getPrivilegeName());
	}

	@Test
	public void testRequestQueuesACheckForTheRequester() {
		givenViolation(7L, "Betterleaks: github-pat");
		BDDMockito.when(repository.findByViolationId(7L)).thenReturn(Optional.empty());

		Assertions.assertEquals(LiveVerificationStatus.PENDING,
				service.request(SCAN, 7L, "alice"));

		BetterleaksVerificationEntity entity = saved();
		Assertions.assertEquals(7L, entity.getViolationId());
		Assertions.assertEquals(BetterleaksVerificationState.PENDING, entity.getState());
		Assertions.assertEquals("alice", entity.getRequestedBy());
		Assertions.assertEquals(NOW.toEpochMilli(), entity.getNextAttemptAt());
		Assertions.assertEquals(0, entity.getAttempts());
	}

	@Test
	public void testAFindingFromAnotherScanIsUnknown() {
		// The report id in the URL must be the finding's own scan.
		givenViolation(7L, "Betterleaks: github-pat");

		IllegalArgumentException e = Assertions.assertThrows(IllegalArgumentException.class,
				() -> service.request(SCAN + 1, 7L, "alice"));
		Assertions.assertEquals("Unknown finding.", e.getMessage());
		BDDMockito.verify(repository, BDDMockito.never()).save(BDDMockito.any());
	}

	@Test
	public void testEachUserHasAnHourlyBudget() {
		givenViolation(7L, "Betterleaks: github-pat");
		BDDMockito.when(repository.findByViolationId(7L)).thenReturn(Optional.empty());
		BDDMockito.when(repository.countByRequestedByAndRequestedAtGreaterThan("alice",
				NOW.toEpochMilli() - HOUR)).thenReturn((long) BUDGET);

		IllegalArgumentException e = Assertions.assertThrows(IllegalArgumentException.class,
				() -> service.request(SCAN, 7L, "alice"));
		MatcherAssert.assertThat(e.getMessage(), Matchers.containsString("last hour"));
		BDDMockito.verify(repository, BDDMockito.never()).save(BDDMockito.any());
	}

	@Test
	public void testRequestingAgainWhileQueuedDoesNothingAndCostsNothing() {
		givenViolation(7L, "Betterleaks: github-pat");
		BetterleaksVerificationEntity running = new BetterleaksVerificationEntity();
		running.setState(BetterleaksVerificationState.RUNNING);
		BDDMockito.when(repository.findByViolationId(7L)).thenReturn(Optional.of(running));

		Assertions.assertEquals(LiveVerificationStatus.PENDING, service.request(SCAN, 7L, "bob"));

		BDDMockito.verify(repository, BDDMockito.never()).save(BDDMockito.any());
		BDDMockito.verify(repository, BDDMockito.never())
				.countByRequestedByAndRequestedAtGreaterThan(BDDMockito.any(),
						BDDMockito.anyLong());
	}

	@Test
	public void testReRequestingAFinishedCheckRequeuesItButKeepsItsNotification() {
		givenViolation(7L, "Betterleaks: github-pat");
		BetterleaksVerificationEntity done = new BetterleaksVerificationEntity();
		done.setViolationId(7L);
		done.setState(BetterleaksVerificationState.LIVE);
		done.setAttempts(2);
		done.setNotifiedAt(123L);
		done.setLastError("old");
		BDDMockito.when(repository.findByViolationId(7L)).thenReturn(Optional.of(done));

		service.request(SCAN, 7L, "bob");

		BetterleaksVerificationEntity entity = saved();
		Assertions.assertEquals(BetterleaksVerificationState.PENDING, entity.getState());
		Assertions.assertEquals(0, entity.getAttempts());
		Assertions.assertNull(entity.getLastError());
		// A secret already reported live is not announced again.
		Assertions.assertEquals(123L, entity.getNotifiedAt());
	}

	@Test
	public void testRulesSecurityDidNotAllowAreRefused() {
		givenViolation(7L, "Betterleaks: custom-internal-token");
		givenViolation(8L, "Betterleaks: gitlab-pat");

		Assertions.assertThrows(IllegalArgumentException.class,
				() -> service.request(SCAN, 7L, "a"));
		Assertions.assertThrows(IllegalArgumentException.class,
				() -> service.request(SCAN, 8L, "a"));
		BDDMockito.verify(repository, BDDMockito.never()).save(BDDMockito.any());
	}

	@Test
	public void testUnknownOrForeignFindingsAreRefused() {
		BDDMockito.when(violations.findById(1L)).thenReturn(Optional.empty());
		givenViolation(2L, "Regex: AWS key");

		Assertions.assertThrows(IllegalArgumentException.class,
				() -> service.request(SCAN, 1L, "a"));
		Assertions.assertThrows(IllegalArgumentException.class,
				() -> service.request(SCAN, 2L, "a"));
		BDDMockito.verify(repository, BDDMockito.never()).save(BDDMockito.any());
	}

	@Test
	public void testAConcurrentDuplicateRequestIsAlreadyQueued() {
		givenViolation(7L, "Betterleaks: github-pat");
		BDDMockito.when(repository.findByViolationId(7L)).thenReturn(Optional.empty());
		BDDMockito.when(repository.save(BDDMockito.any()))
				.thenThrow(new DataIntegrityViolationException("duplicate"));

		Assertions.assertEquals(LiveVerificationStatus.PENDING,
				service.request(SCAN, 7L, "alice"));
	}

	@Test
	public void testStatusesMapEachRequestedViolation() {
		BetterleaksVerificationEntity live = new BetterleaksVerificationEntity();
		live.setViolationId(7L);
		live.setState(BetterleaksVerificationState.LIVE);
		BetterleaksVerificationEntity running = new BetterleaksVerificationEntity();
		running.setViolationId(8L);
		running.setState(BetterleaksVerificationState.RUNNING);
		BDDMockito.when(repository.findByViolationIdIn(List.of(7L, 8L, 9L)))
				.thenReturn(List.of(live, running));

		Assertions.assertEquals(Map.of(7L, LiveVerificationStatus.LIVE,
				8L, LiveVerificationStatus.PENDING), service.getStatuses(List.of(7L, 8L, 9L)));
	}
}
