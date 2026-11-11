package com.tracelink.appsec.module.betterleaks.verify;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import org.hamcrest.MatcherAssert;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.BDDMockito;

import com.tracelink.appsec.module.betterleaks.alerting.BetterleaksAlertListener;
import com.tracelink.appsec.module.betterleaks.engine.BetterleaksEngine;
import com.tracelink.appsec.module.betterleaks.engine.BetterleaksScanException;
import com.tracelink.appsec.module.betterleaks.engine.BetterleaksValidation;
import com.tracelink.appsec.watchtower.core.alerting.AlertEvent;
import com.tracelink.appsec.watchtower.core.alerting.AlertService;
import com.tracelink.appsec.watchtower.core.alerting.AlertTypeRegistry;
import com.tracelink.appsec.watchtower.core.rule.RulePriority;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.ApiIntegrationService;
import com.tracelink.appsec.watchtower.core.scan.code.scm.api.AbstractScmIntegrationEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.api.IScmApi;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.PullRequest;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.entity.PullRequestContainerEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.entity.PullRequestScanEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.entity.PullRequestViolationEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.repository.PRViolationRepository;

public class BetterleaksVerificationWorkerTest {

	private static final Instant NOW = Instant.parse("2026-09-25T12:00:00Z");

	private static final long MINUTE = 60_000L;

	/** Line 12 of a 30-line file: the window is lines 7-17, so it is line 6 of the window. */
	private static final int FLAGGED_LINE = 12;

	private static final int WINDOW_LINE = 6;

	private static final VerifiableRules ALLOWED =
			new VerifiableRules("github-pat", Set.of("github-pat"));

	private BetterleaksVerificationRepository repository;

	private PRViolationRepository violations;

	private ApiIntegrationService integrations;

	private BetterleaksEngine engine;

	private AlertService alertService;

	private IScmApi api;

	private PullRequestScanEntity scan;

	private BetterleaksVerificationWorker worker;

	/** Every directory the engine was pointed at, to check they are cleaned up. */
	private final List<Path> validatedDirs = new ArrayList<>();

	@BeforeEach
	public void setup() throws Exception {
		repository = BDDMockito.mock(BetterleaksVerificationRepository.class);
		violations = BDDMockito.mock(PRViolationRepository.class);
		integrations = BDDMockito.mock(ApiIntegrationService.class);
		engine = BDDMockito.mock(BetterleaksEngine.class);
		alertService = BDDMockito.mock(AlertService.class);
		api = BDDMockito.mock(IScmApi.class);
		worker = new BetterleaksVerificationWorker(repository, violations, integrations,
				ALLOWED, engine, alertService, new AlertTypeRegistry(), "https://wt.example.com",
				null, Clock.fixed(NOW, ZoneOffset.UTC));

		PullRequestContainerEntity container = BDDMockito.mock(PullRequestContainerEntity.class);
		BDDMockito.when(container.getApiLabel()).thenReturn("bb-cloud");
		BDDMockito.when(container.toPullRequest()).thenAnswer(invocation -> {
			PullRequest pr = new PullRequest("bb-cloud");
			pr.setRepoName("payments");
			pr.setPrId("42");
			return pr;
		});
		scan = BDDMockito.mock(PullRequestScanEntity.class);
		BDDMockito.when(scan.getId()).thenReturn(77L);
		BDDMockito.when(scan.getCommitHash()).thenReturn("abc123");
		BDDMockito.when(scan.getContainer()).thenReturn(container);
		PullRequestViolationEntity violation = BDDMockito.mock(PullRequestViolationEntity.class);
		BDDMockito.when(violation.getViolationName()).thenReturn("Betterleaks: github-pat");
		BDDMockito.when(violation.getFileName()).thenReturn("src/config.yml");
		BDDMockito.when(violation.getLineNum()).thenReturn(FLAGGED_LINE);
		BDDMockito.when(violation.getSeverity()).thenReturn(RulePriority.HIGH);
		BDDMockito.when(violation.getScan()).thenReturn(scan);
		BDDMockito.when(violations.findById(7L)).thenReturn(Optional.of(violation));

		AbstractScmIntegrationEntity integration =
				BDDMockito.mock(AbstractScmIntegrationEntity.class);
		BDDMockito.when(integration.createApi()).thenReturn(api);
		BDDMockito.when(integrations.findByLabel("bb-cloud")).thenReturn(integration);
		BDDMockito.when(api.sendComment(BDDMockito.any(), BDDMockito.any())).thenReturn(true);
		BDDMockito.doAnswer(invocation -> {
			Path target = invocation.getArgument(2);
			Path file = target.resolve((String) invocation.getArgument(1));
			Files.createDirectories(file.getParent());
			StringBuilder content = new StringBuilder();
			for (int i = 1; i <= 30; i++) {
				content.append(i == FLAGGED_LINE ? "token = REDACTED-IN-TEST" : "line " + i)
						.append('\n');
			}
			Files.writeString(file, content);
			return null;
		}).when(api).downloadFileAtCommit(BDDMockito.any(), BDDMockito.any(), BDDMockito.any());
	}

	private BetterleaksVerificationEntity queued(int previousAttempts) {
		BetterleaksVerificationEntity verification = new BetterleaksVerificationEntity();
		verification.setViolationId(7L);
		verification.setState(BetterleaksVerificationState.PENDING);
		verification.setAttempts(previousAttempts);
		verification.setRequestedBy("alice");
		BDDMockito.when(repository.findTop10ByStateAndNextAttemptAtLessThanEqualOrderByNextAttemptAtAsc(
				BetterleaksVerificationState.PENDING, NOW.toEpochMilli()))
				.thenReturn(List.of(verification));
		BDDMockito.when(repository.claim(BDDMockito.anyLong(), BDDMockito.anyLong(),
				BDDMockito.anyLong(), BDDMockito.any(), BDDMockito.any())).thenReturn(1);
		return verification;
	}

	private void givenProviderSays(String status, int line) throws Exception {
		BDDMockito.when(engine.validate(BDDMockito.any(), BDDMockito.eq("github-pat")))
				.thenAnswer(invocation -> {
					Path dir = invocation.getArgument(0);
					validatedDirs.add(dir);
					String window = Files.readString(dir.resolve("window.txt"));
					Assertions.assertEquals(11, window.lines().count());
					Assertions.assertEquals("token = REDACTED-IN-TEST",
							window.lines().toList().get(WINDOW_LINE - 1));
					return List.of(new BetterleaksValidation("github-pat", "window.txt", line,
							status));
				});
	}

	private List<AlertEvent> alerts(int times) {
		ArgumentCaptor<AlertEvent> captor = ArgumentCaptor.forClass(AlertEvent.class);
		BDDMockito.verify(alertService, BDDMockito.times(times)).raise(captor.capture());
		return captor.getAllValues();
	}

	@Test
	public void testRegistersItsAlertTypes() {
		AlertTypeRegistry registry = new AlertTypeRegistry();
		new BetterleaksVerificationWorker(repository, violations, integrations, ALLOWED, engine,
				alertService, registry, null, null, Clock.systemUTC());

		Assertions.assertTrue(registry.get(BetterleaksVerificationWorker.SECRET_LIVE).isPresent());
		Assertions.assertTrue(
				registry.get(BetterleaksVerificationWorker.VERIFICATION_FAILED).isPresent());
	}

	@Test
	public void testALiveSecretIsCommentedAlertedOnceAndTheWorkIsCleanedUp() throws Exception {
		BetterleaksVerificationEntity verification = queued(0);
		givenProviderSays("valid", WINDOW_LINE);

		worker.poll();

		Assertions.assertEquals(BetterleaksVerificationState.LIVE, verification.getState());
		Assertions.assertEquals(NOW.toEpochMilli(), verification.getNotifiedAt());
		Assertions.assertNull(verification.getLeaseUntil());
		BDDMockito.verify(repository).save(verification);
		ArgumentCaptor<PullRequest> pr = ArgumentCaptor.forClass(PullRequest.class);
		ArgumentCaptor<String> comment = ArgumentCaptor.forClass(String.class);
		BDDMockito.verify(api).sendComment(pr.capture(), comment.capture());
		Assertions.assertEquals("abc123", pr.getValue().getCommitHash());
		MatcherAssert.assertThat(comment.getValue(), Matchers.containsString("github-pat"));
		MatcherAssert.assertThat(comment.getValue(), Matchers.containsString("src/config.yml"));
		MatcherAssert.assertThat(comment.getValue(),
				Matchers.not(Matchers.containsString("REDACTED-IN-TEST")));
		AlertEvent alert = alerts(1).get(0);
		Assertions.assertEquals(BetterleaksVerificationWorker.SECRET_LIVE, alert.type());
		Assertions.assertEquals("https://wt.example.com/scan/report/77", alert.link());
		PullRequest threadPr = new PullRequest("bb-cloud");
		threadPr.setRepoName("payments");
		threadPr.setPrId("42");
		Assertions.assertEquals(BetterleaksAlertListener.threadKey(threadPr), alert.threadKey());
		Assertions.assertEquals(RulePriority.HIGH, alert.items().get(0).priority());
		BDDMockito.verify(api).downloadFileAtCommit(BDDMockito.any(),
				BDDMockito.eq("src/config.yml"), BDDMockito.any());
		Assertions.assertFalse(Files.exists(validatedDirs.get(0)),
				"the checked text must not stay on disk");
	}

	@Test
	public void testALiveSecretAlreadyAnnouncedIsNotAnnouncedAgain() throws Exception {
		BetterleaksVerificationEntity verification = queued(0);
		verification.setNotifiedAt(1L);
		givenProviderSays("valid", WINDOW_LINE);

		worker.poll();

		Assertions.assertEquals(BetterleaksVerificationState.LIVE, verification.getState());
		BDDMockito.verify(api, BDDMockito.never()).sendComment(BDDMockito.any(), BDDMockito.any());
		BDDMockito.verifyNoInteractions(alertService);
	}

	@Test
	public void testARejectedSecretIsRecordedQuietly() throws Exception {
		BetterleaksVerificationEntity verification = queued(0);
		givenProviderSays("revoked", WINDOW_LINE);

		worker.poll();

		Assertions.assertEquals(BetterleaksVerificationState.INVALID, verification.getState());
		Assertions.assertEquals(NOW.toEpochMilli(), verification.getVerifiedAt());
		BDDMockito.verifyNoInteractions(alertService);
	}

	@Test
	public void testAFindingOnAnotherLineIsNotTheScannedSecret() throws Exception {
		BetterleaksVerificationEntity verification = queued(0);
		givenProviderSays("valid", WINDOW_LINE + 1);

		worker.poll();

		Assertions.assertEquals(BetterleaksVerificationState.UNVERIFIABLE,
				verification.getState());
		BDDMockito.verifyNoInteractions(alertService);
	}

	@Test
	public void testARuleNoLongerAllowedIsNeverSentToItsProvider() throws Exception {
		BetterleaksVerificationEntity verification = queued(0);
		BetterleaksVerificationWorker restricted = new BetterleaksVerificationWorker(repository,
				violations, integrations, new VerifiableRules("", Set.of("github-pat")), engine,
				alertService, new AlertTypeRegistry(), null, null,
				Clock.fixed(NOW, ZoneOffset.UTC));

		restricted.poll();

		Assertions.assertEquals(BetterleaksVerificationState.UNVERIFIABLE,
				verification.getState());
		BDDMockito.verifyNoInteractions(engine);
		BDDMockito.verify(api, BDDMockito.never()).downloadFileAtCommit(BDDMockito.any(),
				BDDMockito.any(), BDDMockito.any());
	}

	@Test
	public void testAScanWithoutACommitCannotBeVerified() throws Exception {
		BetterleaksVerificationEntity verification = queued(0);
		BDDMockito.when(scan.getCommitHash()).thenReturn(null);

		worker.poll();

		Assertions.assertEquals(BetterleaksVerificationState.UNVERIFIABLE,
				verification.getState());
		BDDMockito.verifyNoInteractions(engine);
	}

	@Test
	public void testAFileGoneAtTheScannedCommitIsUnverifiableNotAFailure() throws Exception {
		// The SCM answered 404 (downloadFileAtCommit writes nothing): e.g. the secret's file was
		// deleted or renamed. Nothing to check, so no retries and no failure alert.
		BetterleaksVerificationEntity verification = queued(0);
		BDDMockito.doNothing().when(api).downloadFileAtCommit(BDDMockito.any(), BDDMockito.any(),
				BDDMockito.any());

		worker.poll();

		Assertions.assertEquals(BetterleaksVerificationState.UNVERIFIABLE,
				verification.getState());
		BDDMockito.verifyNoInteractions(engine, alertService);
	}

	@Test
	public void testAFetchFailureIsRetriedLater() throws Exception {
		BetterleaksVerificationEntity verification = queued(0);
		BDDMockito.doThrow(new java.io.IOException("Response code is 503"))
				.when(api).downloadFileAtCommit(BDDMockito.any(), BDDMockito.any(),
						BDDMockito.any());

		worker.poll();

		Assertions.assertEquals(BetterleaksVerificationState.PENDING, verification.getState());
		Assertions.assertEquals(1, verification.getAttempts());
		Assertions.assertEquals(NOW.toEpochMilli() + MINUTE, verification.getNextAttemptAt());
		MatcherAssert.assertThat(verification.getLastError(), Matchers.containsString("503"));
		BDDMockito.verifyNoInteractions(alertService);
	}

	@Test
	public void testABinaryFileIsNotChecked() throws Exception {
		BetterleaksVerificationEntity verification = queued(0);
		BDDMockito.doAnswer(invocation -> {
			Path target = invocation.getArgument(2);
			Path file = target.resolve((String) invocation.getArgument(1));
			Files.createDirectories(file.getParent());
			Files.write(file, new byte[] {'a', '\n', 0, 'b', '\n'});
			return null;
		}).when(api).downloadFileAtCommit(BDDMockito.any(), BDDMockito.any(), BDDMockito.any());

		worker.poll();

		Assertions.assertEquals(BetterleaksVerificationState.UNVERIFIABLE,
				verification.getState());
		BDDMockito.verifyNoInteractions(engine);
	}

	@Test
	public void testAProviderErrorIsRetriedWithBackoff() throws Exception {
		BetterleaksVerificationEntity verification = queued(1);
		givenProviderSays("error", WINDOW_LINE);

		worker.poll();

		Assertions.assertEquals(BetterleaksVerificationState.PENDING, verification.getState());
		Assertions.assertEquals(NOW.toEpochMilli() + 5 * MINUTE, verification.getNextAttemptAt());
	}

	@Test
	public void testTheLastFailedAttemptGivesUpAndAlerts() throws Exception {
		BetterleaksVerificationEntity verification = queued(2);
		BDDMockito.when(engine.validate(BDDMockito.any(), BDDMockito.any()))
				.thenThrow(new BetterleaksScanException(BetterleaksScanException.Reason.TIMEOUT,
						"betterleaks timed out after 120s"));

		worker.poll();

		Assertions.assertEquals(BetterleaksVerificationState.ERROR, verification.getState());
		Assertions.assertEquals(3, verification.getAttempts());
		AlertEvent alert = alerts(1).get(0);
		Assertions.assertEquals(BetterleaksVerificationWorker.VERIFICATION_FAILED, alert.type());
		Assertions.assertEquals("payments", alert.repoName());
	}

	@Test
	public void testAJobAnotherInstanceClaimedIsLeftAlone() throws Exception {
		queued(0);
		BDDMockito.when(repository.claim(BDDMockito.anyLong(), BDDMockito.anyLong(),
				BDDMockito.anyLong(), BDDMockito.any(), BDDMockito.any())).thenReturn(0);

		worker.poll();

		BDDMockito.verifyNoInteractions(engine);
		BDDMockito.verify(repository, BDDMockito.never()).save(BDDMockito.any());
	}

	@Test
	public void testEveryPollReleasesExpiredLeases() {
		worker.poll();

		BDDMockito.verify(repository).releaseExpiredLeases(NOW.toEpochMilli(),
				BetterleaksVerificationState.PENDING, BetterleaksVerificationState.RUNNING);
	}

	@Test
	public void testAPollFailureNeverEscapes() {
		BDDMockito.when(repository.releaseExpiredLeases(BDDMockito.anyLong(), BDDMockito.any(),
				BDDMockito.any())).thenThrow(new IllegalStateException("db down"));

		worker.pollSafely();
	}
}
