package com.tracelink.appsec.watchtower.core.scan.code.scm.pr.bypass;

import java.util.ArrayList;
import java.util.List;

import org.hamcrest.MatcherAssert;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.BDDMockito;
import org.springframework.test.util.ReflectionTestUtils;

import com.tracelink.appsec.watchtower.core.scan.apiintegration.ApiIntegrationEntity;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.ApiIntegrationService;
import com.tracelink.appsec.watchtower.core.scan.code.scm.api.IScmApi;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.PullRequest;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.entity.PullRequestContainerEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.entity.PullRequestScanEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.service.PRScanResultService;

import kong.unirest.json.JSONObject;

public class PRCommentCommandServiceTest {

	private PRScanResultService resultService;
	private PRBypassRequestService requestService;
	private IScmApi api;
	private PRCommentCommandService service;
	private PullRequest pr;
	private final List<Runnable> queued = new ArrayList<>();
	private long now = 1_000_000L;

	@BeforeEach
	public void setup() {
		resultService = BDDMockito.mock(PRScanResultService.class);
		requestService = BDDMockito.mock(PRBypassRequestService.class);
		ApiIntegrationService apiService = BDDMockito.mock(ApiIntegrationService.class);
		ApiIntegrationEntity integration = BDDMockito.mock(ApiIntegrationEntity.class);
		api = BDDMockito.mock(IScmApi.class);
		BDDMockito.when(apiService.findByLabel("bb")).thenReturn(integration);
		BDDMockito.when(integration.createApi()).thenReturn(api);
		BDDMockito.when(api.replyToComment(BDDMockito.any(), BDDMockito.anyLong(),
				BDDMockito.anyString())).thenReturn(true);

		pr = new PullRequest("bb");
		pr.setRepoName("payments");
		pr.setPrId("17");
		// Runs nothing until the test says so, like the real single-thread executor.
		service = new PRCommentCommandService(resultService, requestService, apiService,
				"https://wt.example.invalid", queued::add, () -> now);
	}

	private static String comment(String text) {
		return new JSONObject()
				.put("comment", new JSONObject().put("id", 99)
						.put("content", new JSONObject().put("raw", text)))
				.put("actor", new JSONObject().put("display_name", "Dana Dev")
						.put("account_id", "557058:abc"))
				.toString();
	}

	private void givenLatestScan(long scanId) {
		PullRequestContainerEntity container = new PullRequestContainerEntity();
		PullRequestScanEntity scan = new PullRequestScanEntity();
		ReflectionTestUtils.setField(scan, "id", scanId);
		ReflectionTestUtils.setField(container, "scans", List.of(scan));
		BDDMockito.when(resultService.getPullRequestByLabelRepoAndId("bb", "payments", "17"))
				.thenReturn(container);
	}

	private String reply() {
		ArgumentCaptor<String> text = ArgumentCaptor.forClass(String.class);
		BDDMockito.verify(api).replyToComment(BDDMockito.eq(pr), BDDMockito.eq(99L),
				text.capture());
		return text.getValue();
	}

	private void runQueued() {
		queued.forEach(Runnable::run);
	}

	@Test
	public void testOrdinaryCommentsCostNothing() {
		Assertions.assertFalse(service.submit(pr, comment("Looks good to me")));

		Assertions.assertTrue(queued.isEmpty(), "nothing is queued for a normal comment");
		BDDMockito.verifyNoInteractions(resultService, requestService, api);
	}

	@Test
	public void testCommandIsHandledOffTheWebhookThread() {
		givenLatestScan(5);

		Assertions.assertTrue(service.submit(pr, comment("/watchtower bypass Test fixture")));

		BDDMockito.verifyNoInteractions(requestService, api);
		runQueued();
		BDDMockito.verify(requestService).request(5L, "Dana Dev", "Test fixture",
				RequestSource.PR_COMMENT, "557058:abc");
		MatcherAssert.assertThat(reply(), Matchers.allOf(
				Matchers.containsString("Bypass requested"),
				Matchers.containsString("https://wt.example.invalid/scan/report/5")));
	}

	@Test
	public void testRefusalIsTheReply() {
		givenLatestScan(5);
		BDDMockito.when(requestService.request(BDDMockito.anyLong(), BDDMockito.any(),
				BDDMockito.any(), BDDMockito.any(), BDDMockito.any()))
				.thenThrow(new PRScanBypassException(
						"A bypass request is already pending for this pull request."));

		service.submit(pr, comment("/watchtower bypass again"));
		runQueued();

		MatcherAssert.assertThat(reply(), Matchers.allOf(
				Matchers.containsString("not requested"),
				Matchers.containsString("already pending")));
	}

	@Test
	public void testMissingReasonExplainsTheCommand() {
		givenLatestScan(5);

		service.submit(pr, comment("/watchtower bypass"));
		runQueued();

		BDDMockito.verifyNoInteractions(requestService);
		MatcherAssert.assertThat(reply(), Matchers.containsString("/watchtower bypass <reason>"));
	}

	@Test
	public void testUnscannedPullRequest() {
		service.submit(pr, comment("/watchtower bypass Hotfix"));
		runQueued();

		BDDMockito.verifyNoInteractions(requestService);
		MatcherAssert.assertThat(reply(), Matchers.containsString("no scan"));
	}

	@Test
	public void testMentionThatIsNotACommandGetsNoReply() {
		service.submit(pr, comment("Comment /watchtower bypass to skip it"));
		runQueued();

		BDDMockito.verifyNoInteractions(requestService, api);
	}

	@Test
	public void testBrokenPayloadIsIgnored() {
		service.submit(pr, "{\"comment\": \"/watchtower bypass\"");
		runQueued();

		BDDMockito.verifyNoInteractions(requestService, api);
	}

	@Test
	public void testFullQueueDropsTheCommandWithoutFailingTheWebhook() {
		PRCommentCommandService full = new PRCommentCommandService(resultService, requestService,
				BDDMockito.mock(ApiIntegrationService.class), null, task -> {
					throw new java.util.concurrent.RejectedExecutionException("full");
				}, () -> now);

		Assertions.assertFalse(full.submit(pr, comment("/watchtower bypass Hotfix")));
	}

	@Test
	public void testRepeatedRefusalsGetOneReplyPerCooldown() {
		// Spamming the command must not spend the Bitbucket quota scans need.
		givenLatestScan(5);
		BDDMockito.when(requestService.request(BDDMockito.anyLong(), BDDMockito.any(),
				BDDMockito.any(), BDDMockito.any(), BDDMockito.any()))
				.thenThrow(new PRScanBypassException("already pending"));

		for (int i = 0; i < 5; i++) {
			service.submit(pr, new JSONObject(comment("/watchtower bypass again"))
					.put("comment", new JSONObject().put("id", 100 + i)
							.put("content", new JSONObject().put("raw", "/watchtower bypass again"))).toString());
		}
		runQueued();
		BDDMockito.verify(api, BDDMockito.times(1)).replyToComment(BDDMockito.any(),
				BDDMockito.anyLong(), BDDMockito.anyString());

		now += PRCommentCommandService.REFUSAL_COOLDOWN_MILLIS;
		queued.clear();
		service.submit(pr, comment("/watchtower bypass again"));
		runQueued();
		BDDMockito.verify(api, BDDMockito.times(2)).replyToComment(BDDMockito.any(),
				BDDMockito.anyLong(), BDDMockito.anyString());
	}

	@Test
	public void testASuccessfulRequestIsAlwaysAnswered() {
		givenLatestScan(5);
		BDDMockito.when(requestService.request(BDDMockito.anyLong(), BDDMockito.any(),
				BDDMockito.any(), BDDMockito.any(), BDDMockito.any()))
				.thenThrow(new PRScanBypassException("Not blocking"))
				.thenReturn(new PullRequestBypassRequestEntity());

		service.submit(pr, comment("/watchtower bypass first"));
		service.submit(pr, new JSONObject(comment("/watchtower bypass second"))
				.put("comment", new JSONObject().put("id", 100)
						.put("content", new JSONObject().put("raw", "/watchtower bypass second"))).toString());
		runQueued();

		BDDMockito.verify(api, BDDMockito.times(2)).replyToComment(BDDMockito.any(),
				BDDMockito.anyLong(), BDDMockito.anyString());
	}

	@Test
	public void duplicateWorkspaceAndRepositoryDeliveryQueuesOneCommandAndCountsIt() {
		givenLatestScan(5);
		var meters = new io.micrometer.core.instrument.simple.SimpleMeterRegistry();
		var apiService = BDDMockito.mock(ApiIntegrationService.class);
		var integration = BDDMockito.mock(ApiIntegrationEntity.class);
		BDDMockito.when(apiService.findByLabel("bb")).thenReturn(integration);
		BDDMockito.when(integration.createApi()).thenReturn(api);
		service = new PRCommentCommandService(resultService, requestService, apiService,
				"https://wt.example", queued::add, () -> now, meters);
		String body = comment("/watchtower bypass Hotfix");
		Assertions.assertTrue(service.submit(pr, body));
		Assertions.assertFalse(service.submit(pr, body));
		Assertions.assertEquals(1, queued.size());
		Assertions.assertEquals(1.0, meters.get("watchtower.webhook.comment.duplicates").counter().count());
		runQueued();
		BDDMockito.verify(requestService, BDDMockito.times(1)).request(5L, "Dana Dev", "Hotfix",
				RequestSource.PR_COMMENT, "557058:abc");
		BDDMockito.verify(api, BDDMockito.times(1)).replyToComment(BDDMockito.any(), BDDMockito.eq(99L), BDDMockito.anyString());
	}

	@Test
	public void duplicateSuppressionExpiresAndStaysBounded() {
		String body = comment("/watchtower bypass Hotfix");
		Assertions.assertTrue(service.submit(pr, body));
		Assertions.assertFalse(service.submit(pr, body));
		now += PRCommentCommandService.COMMENT_DEDUP_MILLIS;
		Assertions.assertTrue(service.submit(pr, body));
		for (int i = 0; i < PRCommentCommandService.MAX_RECENT_COMMENTS; i++) {
			String distinct = body.replace("\"id\":99", "\"id\":" + (100 + i));
			service.submit(pr, distinct);
		}
		// The oldest reservation was evicted; no unbounded map of comment ids accumulates.
		Assertions.assertTrue(service.submit(pr, body));
	}

	@Test
	public void concurrentDuplicateDeliveriesQueueOnlyOnce() throws Exception {
		String body = comment("/watchtower bypass Hotfix");
		try (var pool = java.util.concurrent.Executors.newFixedThreadPool(8)) {
			var futures = new java.util.ArrayList<java.util.concurrent.Future<Boolean>>();
			for (int i = 0; i < 32; i++) futures.add(pool.submit(() -> service.submit(pr, body)));
			long accepted = 0;
			for (var future : futures) if (future.get()) accepted++;
			Assertions.assertEquals(1, accepted);
		}
		Assertions.assertEquals(1, queued.size());
	}

	@Test
	public void commentIdsAreScopedToRepositoryAndPullRequest() {
		String body = comment("/watchtower bypass Hotfix");
		service.submit(pr, body);
		PullRequest other = new PullRequest("bb");
		other.setRepoName("different"); other.setPrId("17");
		Assertions.assertTrue(service.submit(other, body));
		other.setPrId("18");
		Assertions.assertTrue(service.submit(other, body));
		Assertions.assertEquals(3, queued.size());
	}

	@Test
	public void rejectedEnqueueDoesNotSuppressLaterRetry() {
		var attempts = new java.util.concurrent.atomic.AtomicInteger();
		service = new PRCommentCommandService(resultService, requestService,
				BDDMockito.mock(ApiIntegrationService.class), null, task -> {
					if (attempts.getAndIncrement() == 0) throw new java.util.concurrent.RejectedExecutionException();
					queued.add(task);
				}, () -> now);
		String body = comment("/watchtower bypass Hotfix");
		Assertions.assertFalse(service.submit(pr, body));
		Assertions.assertTrue(service.submit(pr, body));
		Assertions.assertEquals(1, queued.size());
	}

	@Test
	public void testDisplayNameCannotForgeLogLines() {
		givenLatestScan(5);
		String payload = new JSONObject(comment("/watchtower bypass Hotfix"))
				.put("actor", new JSONObject().put("display_name", "Dana\r\nFAKE LOG LINE\u0007")
						.put("account_id", "1"))
				.toString();

		service.submit(pr, payload);
		runQueued();

		BDDMockito.verify(requestService).request(5L, "Dana FAKE LOG LINE", "Hotfix",
				RequestSource.PR_COMMENT, "1");
	}

	@Test
	public void testRequesterNameIsEscapedInTheReply() {
		givenLatestScan(5);
		String payload = new JSONObject(comment("/watchtower bypass Hotfix"))
				.put("actor", new JSONObject().put("display_name", "[x](http://evil)")
						.put("account_id", "1"))
				.toString();

		service.submit(pr, payload);
		runQueued();

		MatcherAssert.assertThat(reply(), Matchers.not(Matchers.containsString("[x](http")));
	}
}
