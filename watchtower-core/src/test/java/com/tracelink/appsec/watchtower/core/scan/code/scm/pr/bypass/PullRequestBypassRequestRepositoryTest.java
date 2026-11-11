package com.tracelink.appsec.watchtower.core.scan.code.scm.pr.bypass;

import java.util.Optional;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.transaction.annotation.Transactional;

import com.tracelink.appsec.watchtower.core.WatchtowerTestApplication;

import jakarta.persistence.EntityManager;

/**
 * Persists bypass requests through the real Flyway schema (V052).
 */
@ExtendWith(SpringExtension.class)
@SpringBootTest(classes = WatchtowerTestApplication.class)
@Transactional
public class PullRequestBypassRequestRepositoryTest {

	@Autowired
	private PullRequestBypassRequestRepository repository;

	@Autowired
	private EntityManager entityManager;

	private PullRequestBypassRequestEntity request(String prId, long createdAt,
			BypassRequestStatus status) {
		PullRequestBypassRequestEntity request = new PullRequestBypassRequestEntity();
		request.setApiLabel("bb");
		request.setRepoName("payments");
		request.setPrId(prId);
		request.setScanId(5L);
		request.setRequestedBy("dev");
		request.setReason("r".repeat(PullRequestBypassEntity.MAX_REASON_LENGTH));
		request.setCreatedAt(createdAt);
		request.setStatus(status);
		return request;
	}

	private long save(PullRequestBypassRequestEntity request) {
		return repository.saveAndFlush(request).getId();
	}

	@Test
	public void testRoundTripsWithDecision() {
		PullRequestBypassRequestEntity request = request("17", 1000L, BypassRequestStatus.PENDING);
		request.decide(BypassRequestStatus.DECLINED, "lead", 2000L, "n".repeat(1000));
		long id = save(request);
		entityManager.clear();

		PullRequestBypassRequestEntity found = repository.findById(id).orElseThrow();
		Assertions.assertEquals("17", found.getPrId());
		Assertions.assertEquals(5L, found.getScanId());
		Assertions.assertEquals("dev", found.getRequestedBy());
		Assertions.assertEquals(1000, found.getReason().length());
		Assertions.assertEquals(BypassRequestStatus.DECLINED, found.getStatus());
		Assertions.assertEquals("lead", found.getDecidedBy());
		Assertions.assertEquals(2000L, found.getDecidedAt());
		Assertions.assertEquals(1000, found.getDecisionNote().length());
	}

	@Test
	public void testRoundTripsTheSourceOfACommentRequest() {
		PullRequestBypassRequestEntity request = request("18", 1000L, BypassRequestStatus.PENDING);
		request.setSource(RequestSource.PR_COMMENT);
		request.setRequesterScmId("a".repeat(64));
		long id = save(request);
		entityManager.clear();

		PullRequestBypassRequestEntity found = repository.findById(id).orElseThrow();
		Assertions.assertEquals(RequestSource.PR_COMMENT, found.getSource());
		Assertions.assertEquals(64, found.getRequesterScmId().length());
	}

	@Test
	public void testReportRequestsDefaultToWatchtower() {
		long id = save(request("19", 1000L, BypassRequestStatus.PENDING));
		entityManager.clear();

		PullRequestBypassRequestEntity found = repository.findById(id).orElseThrow();
		Assertions.assertEquals(RequestSource.WATCHTOWER, found.getSource());
		Assertions.assertNull(found.getRequesterScmId());
	}

	@Test
	public void testDatabaseAllowsOnlyOnePendingRequestPerPullRequest() {
		PullRequestBypassRequestEntity first = request("17", 1000L, BypassRequestStatus.PENDING);
		first.setPendingKey(PullRequestBypassRequestEntity.pendingKey("bb", "payments", "17"));
		save(first);
		PullRequestBypassRequestEntity second = request("17", 2000L, BypassRequestStatus.PENDING);
		second.setPendingKey(PullRequestBypassRequestEntity.pendingKey("bb", "payments", "17"));

		Assertions.assertThrows(DataIntegrityViolationException.class, () -> save(second));
	}

	@Test
	public void testClosedRequestsDoNotHoldThePendingSlot() {
		PullRequestBypassRequestEntity first = request("17", 1000L, BypassRequestStatus.PENDING);
		first.setPendingKey(PullRequestBypassRequestEntity.pendingKey("bb", "payments", "17"));
		long firstId = save(first);

		Assertions.assertEquals(1, repository.close(firstId, BypassRequestStatus.DECLINED,
				"lead", 2000L, "no", BypassRequestStatus.PENDING));
		entityManager.clear();
		PullRequestBypassRequestEntity second = request("17", 3000L, BypassRequestStatus.PENDING);
		second.setPendingKey(PullRequestBypassRequestEntity.pendingKey("bb", "payments", "17"));
		save(second);

		PullRequestBypassRequestEntity closed = repository.findById(firstId).orElseThrow();
		Assertions.assertEquals(BypassRequestStatus.DECLINED, closed.getStatus());
		Assertions.assertEquals("lead", closed.getDecidedBy());
		Assertions.assertNull(closed.getPendingKey());
	}

	@Test
	public void testOnlyOneDecisionWins() {
		PullRequestBypassRequestEntity request = request("17", 1000L, BypassRequestStatus.PENDING);
		long id = save(request);

		Assertions.assertEquals(1, repository.close(id, BypassRequestStatus.APPROVED, "lead",
				2000L, null, BypassRequestStatus.PENDING));
		Assertions.assertEquals(0, repository.close(id, BypassRequestStatus.DECLINED, "other",
				2001L, null, BypassRequestStatus.PENDING));
	}

	@Test
	public void testReopenRestoresTheRequest() {
		PullRequestBypassRequestEntity request = request("17", 1000L, BypassRequestStatus.PENDING);
		long id = save(request);
		repository.close(id, BypassRequestStatus.APPROVED, "lead", 2000L, null,
				BypassRequestStatus.PENDING);
		String key = PullRequestBypassRequestEntity.pendingKey("bb", "payments", "17");

		Assertions.assertEquals(1, repository.reopen(id, key, BypassRequestStatus.APPROVED,
				BypassRequestStatus.PENDING));
		entityManager.clear();

		PullRequestBypassRequestEntity found = repository.findById(id).orElseThrow();
		Assertions.assertEquals(BypassRequestStatus.PENDING, found.getStatus());
		Assertions.assertNull(found.getDecidedBy());
		Assertions.assertEquals(key, found.getPendingKey());
	}

	@Test
	public void testPendingKeyIsAFixedLengthHash() {
		String key = PullRequestBypassRequestEntity.pendingKey("bb", "payments", "17");

		Assertions.assertEquals(64, key.length());
		Assertions.assertNotEquals(key,
				PullRequestBypassRequestEntity.pendingKey("bb", "payments", "18"));
	}

	@Test
	public void testFindsTheNewestPendingRequestOfThePullRequest() {
		save(request("17", 1000L, BypassRequestStatus.PENDING));
		long newest = save(request("17", 3000L, BypassRequestStatus.PENDING));
		save(request("17", 5000L, BypassRequestStatus.DECLINED));
		save(request("18", 6000L, BypassRequestStatus.PENDING));
		entityManager.clear();

		Optional<PullRequestBypassRequestEntity> found = repository
				.findFirstByApiLabelAndRepoNameAndPrIdAndStatusOrderByCreatedAtDesc("bb",
						"payments", "17", BypassRequestStatus.PENDING);

		Assertions.assertEquals(newest, found.orElseThrow().getId());
	}
}
