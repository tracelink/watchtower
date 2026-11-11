package com.tracelink.appsec.watchtower.core.scan.code.scm.pr.bypass;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import org.hamcrest.MatcherAssert;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.BDDMockito;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.test.util.ReflectionTestUtils;

import com.tracelink.appsec.watchtower.core.alerting.AlertEvent;
import com.tracelink.appsec.watchtower.core.alerting.AlertService;
import com.tracelink.appsec.watchtower.core.alerting.AlertTypeRegistry;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.entity.PullRequestContainerEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.entity.PullRequestScanEntity;

public class PRBypassRequestServiceTest {

	private static final Instant NOW = Instant.parse("2026-10-05T12:00:00Z");
	private static final String REASON = "Release blocker; the key is a test fixture";

	private PullRequestBypassRequestRepository repository;
	private PRScanBypassService bypassService;
	private AlertService alertService;
	private AlertTypeRegistry registry;
	private PRBypassRequestService service;
	private PullRequestContainerEntity container;
	private final List<PullRequestScanEntity> scans = new ArrayList<>();
	private PullRequestBypassRequestEntity pending;

	@BeforeEach
	public void setup() {
		repository = BDDMockito.mock(PullRequestBypassRequestRepository.class);
		bypassService = BDDMockito.mock(PRScanBypassService.class);
		alertService = BDDMockito.mock(AlertService.class);
		registry = new AlertTypeRegistry();
		BDDMockito.when(repository.save(BDDMockito.any()))
				.thenAnswer(invocation -> invocation.getArgument(0));
		BDDMockito.when(repository.close(BDDMockito.anyLong(), BDDMockito.any(), BDDMockito.any(),
				BDDMockito.anyLong(), BDDMockito.any(), BDDMockito.any())).thenReturn(1);
		BDDMockito.when(repository.findFirstByApiLabelAndRepoNameAndPrIdAndStatusOrderByCreatedAtDesc(
				"bb", "payments", "17", BypassRequestStatus.PENDING))
				.thenAnswer(invocation -> Optional.ofNullable(
						pending != null && pending.getStatus() == BypassRequestStatus.PENDING
								? pending : null));

		container = new PullRequestContainerEntity();
		container.setApiLabel("bb");
		container.setRepoName("payments");
		container.setPrId("17");
		ReflectionTestUtils.setField(container, "scans", scans);

		service = new PRBypassRequestService(repository, bypassService, alertService, registry,
				"https://wt.example.invalid", Clock.fixed(NOW, ZoneOffset.UTC));
	}

	private PullRequestScanEntity scan(long id) {
		PullRequestScanEntity scan = new PullRequestScanEntity();
		ReflectionTestUtils.setField(scan, "id", id);
		scan.setContainer(container);
		scans.add(scan);
		BDDMockito.when(bypassService.findScan(id)).thenReturn(scan);
		return scan;
	}

	private void givenPending(long scanId, String requester) {
		pending = new PullRequestBypassRequestEntity();
		pending.setApiLabel("bb");
		pending.setRepoName("payments");
		pending.setPrId("17");
		pending.setScanId(scanId);
		pending.setRequestedBy(requester);
		pending.setReason(REASON);
		pending.setCreatedAt(1000L);
	}

	private void assertRefused(Runnable action, String messagePart) {
		PRScanBypassException e =
				Assertions.assertThrows(PRScanBypassException.class, action::run);
		MatcherAssert.assertThat(e.getMessage(), Matchers.containsString(messagePart));
	}

	// --- request ---

	@Test
	public void testRegistersAlertType() {
		Assertions.assertTrue(registry.get(PRBypassRequestService.PR_BYPASS_REQUESTED).isPresent());
	}

	@Test
	public void testRequestIsSavedAlertedAndCounted() {
		scan(5);

		PullRequestBypassRequestEntity saved = service.request(5, "dev", "  " + REASON + " ");

		Assertions.assertEquals("bb", saved.getApiLabel());
		Assertions.assertEquals("payments", saved.getRepoName());
		Assertions.assertEquals("17", saved.getPrId());
		Assertions.assertEquals(5L, saved.getScanId());
		Assertions.assertEquals("dev", saved.getRequestedBy());
		Assertions.assertEquals(REASON, saved.getReason());
		Assertions.assertEquals(NOW.toEpochMilli(), saved.getCreatedAt());
		Assertions.assertEquals(BypassRequestStatus.PENDING, saved.getStatus());
		Assertions.assertEquals(PullRequestBypassRequestEntity.pendingKey("bb", "payments", "17"),
				saved.getPendingKey());
		BDDMockito.verify(bypassService).count("request");
		ArgumentCaptor<AlertEvent> alert = ArgumentCaptor.forClass(AlertEvent.class);
		BDDMockito.verify(alertService).raise(alert.capture());
		Assertions.assertEquals(PRBypassRequestService.PR_BYPASS_REQUESTED, alert.getValue().type());
		Assertions.assertEquals("https://wt.example.invalid/scan/report/5", alert.getValue().link());
		MatcherAssert.assertThat(alert.getValue().title(),
				Matchers.allOf(Matchers.containsString("#17"), Matchers.containsString("dev")));
		MatcherAssert.assertThat(alert.getValue().items().get(0).text(),
				Matchers.containsString(REASON));
	}

	@Test
	public void testRequestFromAPullRequestCommentKeepsItsSource() {
		scan(5);

		PullRequestBypassRequestEntity saved = service.request(5, "Dana Dev", REASON,
				RequestSource.PR_COMMENT, "557058:abc");

		Assertions.assertEquals(RequestSource.PR_COMMENT, saved.getSource());
		Assertions.assertEquals("557058:abc", saved.getRequesterScmId());
		Assertions.assertTrue(saved.isFromPullRequestComment());
		ArgumentCaptor<AlertEvent> alert = ArgumentCaptor.forClass(AlertEvent.class);
		BDDMockito.verify(alertService).raise(alert.capture());
		MatcherAssert.assertThat(alert.getValue().title(),
				Matchers.containsString("Dana Dev via a pull request comment"));
	}

	@Test
	public void testRequestFromTheReportIsAWatchtowerRequest() {
		scan(5);

		PullRequestBypassRequestEntity saved = service.request(5, "dev", REASON);

		Assertions.assertEquals(RequestSource.WATCHTOWER, saved.getSource());
		Assertions.assertNull(saved.getRequesterScmId());
	}

	@Test
	public void testApprovedCommentRequestNamesWhereItCameFrom() {
		scan(5);
		givenPending(5, "Dana Dev");
		pending.setSource(RequestSource.PR_COMMENT);
		BDDMockito.when(bypassService.bypass(BDDMockito.eq(5L), BDDMockito.eq("lead"),
				BDDMockito.anyString())).thenReturn(true);

		service.approve(5, "lead");

		BDDMockito.verify(bypassService).bypass(5, "lead",
				REASON + " (requested by Dana Dev via a pull request comment)");
	}

	@Test
	public void testRequestRefusedForTheSameReasonsAsABypass() {
		PullRequestScanEntity scan = scan(5);
		BDDMockito.when(bypassService.refusalFor(scan)).thenReturn("Rotate it first.");

		assertRefused(() -> service.request(5, "dev", REASON), "Rotate it first.");
		BDDMockito.verify(repository, BDDMockito.never()).save(BDDMockito.any());
	}

	@Test
	public void testRequestNeedsAReason() {
		scan(5);

		assertRefused(() -> service.request(5, "dev", " "), "reason");
	}

	@Test
	public void testOnlyOnePendingRequestPerPullRequest() {
		scan(5);
		givenPending(5, "someone");

		assertRefused(() -> service.request(5, "dev", REASON), "already pending");
	}

	@Test
	public void testConcurrentSecondRequestIsRefusedByTheDatabase() {
		scan(5);
		BDDMockito.when(repository.save(BDDMockito.any()))
				.thenThrow(new DataIntegrityViolationException("uq_pr_bypass_request_pending"));

		assertRefused(() -> service.request(5, "dev", REASON), "already pending");
		BDDMockito.verifyNoInteractions(alertService);
	}

	@Test
	public void testRequestStillSucceedsWhenTheAlertFails() {
		scan(5);
		BDDMockito.doThrow(new IllegalStateException("down")).when(alertService)
				.raise(BDDMockito.any());

		Assertions.assertNotNull(service.request(5, "dev", REASON));
	}

	// --- approve ---

	@Test
	public void testApproveBypassesAsTheApproverAndNamesTheRequester() {
		scan(5);
		givenPending(5, "dev");
		BDDMockito.when(bypassService.bypass(BDDMockito.eq(5L), BDDMockito.eq("lead"),
				BDDMockito.anyString())).thenReturn(true);

		Assertions.assertTrue(service.approve(5, "lead"));

		BDDMockito.verify(bypassService).bypass(5, "lead", REASON + " (requested by dev)");
		Assertions.assertEquals(BypassRequestStatus.APPROVED, pending.getStatus());
		Assertions.assertEquals("lead", pending.getDecidedBy());
		Assertions.assertEquals(NOW.toEpochMilli(), pending.getDecidedAt());
		BDDMockito.verify(bypassService).count("approve");
	}

	@Test
	public void testApprovedReasonFitsTheColumn() {
		scan(5);
		givenPending(5, "dev");
		pending.setReason("r".repeat(PullRequestBypassEntity.MAX_REASON_LENGTH));

		service.approve(5, "lead");

		ArgumentCaptor<String> reason = ArgumentCaptor.forClass(String.class);
		BDDMockito.verify(bypassService).bypass(BDDMockito.eq(5L), BDDMockito.eq("lead"),
				reason.capture());
		Assertions.assertEquals(PullRequestBypassEntity.MAX_REASON_LENGTH,
				reason.getValue().length());
		MatcherAssert.assertThat(reason.getValue(), Matchers.endsWith(" (requested by dev)"));
	}

	@Test
	public void testRequesterCannotApproveTheirOwnRequest() {
		scan(5);
		givenPending(5, "dev");

		assertRefused(() -> service.approve(5, "DEV"), "own request");
		BDDMockito.verify(bypassService, BDDMockito.never()).bypass(BDDMockito.anyLong(),
				BDDMockito.any(), BDDMockito.any());
	}

	@Test
	public void testApproveWithoutAPendingRequest() {
		scan(5);

		assertRefused(() -> service.approve(5, "lead"), "No pending");
	}

	@Test
	public void testANewerScanSupersedesTheRequest() {
		scan(5);
		scan(6);
		givenPending(5, "dev");

		assertRefused(() -> service.approve(6, "lead"), "No pending");
		Assertions.assertEquals(BypassRequestStatus.SUPERSEDED, pending.getStatus());
		BDDMockito.verify(repository).close(BDDMockito.eq(pending.getId()),
				BDDMockito.eq(BypassRequestStatus.SUPERSEDED), BDDMockito.isNull(),
				BDDMockito.eq(NOW.toEpochMilli()), BDDMockito.isNull(),
				BDDMockito.eq(BypassRequestStatus.PENDING));
	}

	// --- the requests list ---

	@Test
	public void testRecentRequestsSupersedesAStalePendingRequestBeforeListing() {
		scan(5);
		scan(6);
		givenPending(5, "dev");
		BDDMockito.when(repository.findByPendingKeyIsNotNull()).thenReturn(List.of(pending));
		BDDMockito.when(repository.findTop200ByOrderByCreatedAtDesc())
				.thenReturn(List.of(pending));

		List<PullRequestBypassRequestEntity> requests = service.recentRequests();

		Assertions.assertEquals(List.of(pending), requests);
		Assertions.assertEquals(BypassRequestStatus.SUPERSEDED, pending.getStatus());
		BDDMockito.verify(repository).close(BDDMockito.eq(pending.getId()),
				BDDMockito.eq(BypassRequestStatus.SUPERSEDED), BDDMockito.isNull(),
				BDDMockito.anyLong(), BDDMockito.isNull(),
				BDDMockito.eq(BypassRequestStatus.PENDING));
	}

	@Test
	public void testRecentRequestsKeepsACurrentPendingRequestPending() {
		scan(5);
		givenPending(5, "dev");
		BDDMockito.when(repository.findByPendingKeyIsNotNull()).thenReturn(List.of(pending));
		BDDMockito.when(repository.findTop200ByOrderByCreatedAtDesc())
				.thenReturn(List.of(pending));

		Assertions.assertEquals(List.of(pending), service.recentRequests());
		Assertions.assertEquals(BypassRequestStatus.PENDING, pending.getStatus());
		BDDMockito.verify(repository, BDDMockito.never()).close(BDDMockito.anyLong(),
				BDDMockito.any(), BDDMockito.any(), BDDMockito.anyLong(), BDDMockito.any(),
				BDDMockito.any());
	}

	@Test
	public void testRecentRequestsStillListsWhenAPendingRequestsScanIsGone() {
		givenPending(99, "dev");
		BDDMockito.when(bypassService.findScan(99L))
				.thenThrow(new PRScanBypassException("Unknown scan."));
		BDDMockito.when(repository.findByPendingKeyIsNotNull()).thenReturn(List.of(pending));
		BDDMockito.when(repository.findTop200ByOrderByCreatedAtDesc())
				.thenReturn(List.of(pending));

		Assertions.assertEquals(List.of(pending), service.recentRequests());
	}

	@Test
	public void testRefusedBypassReopensTheRequest() {
		scan(5);
		givenPending(5, "dev");
		BDDMockito.when(bypassService.bypass(BDDMockito.anyLong(), BDDMockito.any(),
				BDDMockito.any())).thenThrow(new PRScanBypassException("Rotate it first."));

		assertRefused(() -> service.approve(5, "lead"), "Rotate it first.");
		Assertions.assertEquals(BypassRequestStatus.PENDING, pending.getStatus());
		BDDMockito.verify(repository).reopen(pending.getId(),
				PullRequestBypassRequestEntity.pendingKey("bb", "payments", "17"),
				BypassRequestStatus.APPROVED, BypassRequestStatus.PENDING);
	}

	@Test
	public void testOnlyOneOfTwoConcurrentApproversBypasses() {
		scan(5);
		givenPending(5, "dev");
		BDDMockito.when(repository.close(BDDMockito.anyLong(), BDDMockito.any(), BDDMockito.any(),
				BDDMockito.anyLong(), BDDMockito.any(), BDDMockito.any())).thenReturn(0);

		assertRefused(() -> service.approve(5, "lead"), "already decided");
		BDDMockito.verify(bypassService, BDDMockito.never()).bypass(BDDMockito.anyLong(),
				BDDMockito.any(), BDDMockito.any());
		BDDMockito.verify(bypassService, BDDMockito.never()).count("approve");
	}

	@Test
	public void testDeclineLosingTheRaceIsRefused() {
		scan(5);
		givenPending(5, "dev");
		BDDMockito.when(repository.close(BDDMockito.anyLong(), BDDMockito.any(), BDDMockito.any(),
				BDDMockito.anyLong(), BDDMockito.any(), BDDMockito.any())).thenReturn(0);

		assertRefused(() -> service.decline(5, "lead", null), "already decided");
	}

	// --- decline / withdraw ---

	@Test
	public void testDeclineWithANote() {
		scan(5);
		givenPending(5, "dev");

		service.decline(5, "lead", "  Fix it instead ");

		Assertions.assertEquals(BypassRequestStatus.DECLINED, pending.getStatus());
		Assertions.assertEquals("lead", pending.getDecidedBy());
		Assertions.assertEquals("Fix it instead", pending.getDecisionNote());
		BDDMockito.verify(bypassService).count("decline");
	}

	@Test
	public void testDecliningARequestMadeInAPullRequestCommentAnswersThere() {
		scan(5);
		givenPending(5, "dev");
		pending.setSource(RequestSource.PR_COMMENT);

		service.decline(5, "lead", "Fix it instead");

		BDDMockito.verify(bypassService).commentDeclined(5, "lead", "Fix it instead");
	}

	@Test
	public void testDecliningARequestMadeInWatchtowerPostsNothingOnThePullRequest() {
		scan(5);
		givenPending(5, "dev");

		service.decline(5, "lead", null);

		BDDMockito.verify(bypassService, BDDMockito.never()).commentDeclined(BDDMockito.anyLong(),
				BDDMockito.any(), BDDMockito.any());
	}

	@Test
	public void testDeclineNoteIsOptionalButBounded() {
		scan(5);
		givenPending(5, "dev");

		assertRefused(() -> service.decline(5, "lead",
				"n".repeat(PullRequestBypassEntity.MAX_REASON_LENGTH + 1)), "1000");
		service.decline(5, "lead", "  ");
		Assertions.assertNull(pending.getDecisionNote());
	}

	@Test
	public void testRequesterWithdrawsInsteadOfDeclining() {
		scan(5);
		givenPending(5, "dev");

		assertRefused(() -> service.decline(5, "dev", null), "Withdraw");
		service.withdraw(5, "dev");
		Assertions.assertEquals(BypassRequestStatus.WITHDRAWN, pending.getStatus());
	}

	@Test
	public void testOnlyTheRequesterCanWithdraw() {
		scan(5);
		givenPending(5, "dev");

		assertRefused(() -> service.withdraw(5, "other"), "Only the requester");
	}

	// --- stateFor ---

	@Test
	public void testStateShowsThePendingRequestAndWhoIsLooking() {
		scan(5);
		givenPending(5, "dev");

		Assertions.assertTrue(service.stateFor(5, "Dev").viewerIsRequester());
		Assertions.assertFalse(service.stateFor(5, "lead").viewerIsRequester());
		Assertions.assertSame(pending, service.stateFor(5, "lead").pending());
	}

	@Test
	public void testStateWithoutRequestOrScan() {
		scan(5);
		BDDMockito.when(bypassService.findScan(99))
				.thenThrow(new PRScanBypassException("Unknown scan."));

		Assertions.assertNull(service.stateFor(5, "lead").pending());
		Assertions.assertNull(service.stateFor(99, "lead").pending());
	}
}
