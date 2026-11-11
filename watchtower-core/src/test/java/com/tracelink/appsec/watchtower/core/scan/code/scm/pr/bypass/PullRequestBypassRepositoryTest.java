package com.tracelink.appsec.watchtower.core.scan.code.scm.pr.bypass;

import java.util.List;
import java.util.Set;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.transaction.annotation.Transactional;

import com.tracelink.appsec.watchtower.core.WatchtowerTestApplication;
import com.tracelink.appsec.watchtower.core.scan.ScanStatus;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.entity.PullRequestContainerEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.entity.PullRequestScanEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.repository.PRContainerRepository;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.repository.PRScanRepository;

import jakarta.persistence.EntityManager;

/**
 * Persists bypasses through the real Flyway schema (V051) so entity/column mismatches fail here
 * instead of on the deployed database.
 */
@ExtendWith(SpringExtension.class)
@SpringBootTest(classes = WatchtowerTestApplication.class)
@Transactional
public class PullRequestBypassRepositoryTest {

	private static final String API_LABEL = "bb-test";
	private static final String REPO = "repo";

	@Autowired
	private PullRequestBypassRepository bypassRepository;

	@Autowired
	private PRScanRepository scanRepository;

	@Autowired
	private PRContainerRepository containerRepository;

	@Autowired
	private EntityManager entityManager;

	@Test
	public void testBypassRoundTripsWithFindings() {
		long id = save(bypass("pr-1", 42L,
				Set.of(new BypassedFinding("AWS Access Key", "src/config/app.yml"),
						new BypassedFinding("GitHub Token", "scripts/deploy.sh"))));

		PullRequestBypassEntity found = reload(id);

		Assertions.assertEquals(API_LABEL, found.getApiLabel());
		Assertions.assertEquals(REPO, found.getRepoName());
		Assertions.assertEquals("pr-1", found.getPrId());
		Assertions.assertEquals(42L, found.getScanId());
		Assertions.assertEquals("abc123", found.getCommitHash());
		Assertions.assertEquals("alice", found.getBypassedBy());
		Assertions.assertEquals("Hotfix, accepted risk", found.getReason());
		Assertions.assertEquals(1000L, found.getCreatedAt());
		Assertions.assertFalse(found.isRevoked());
		Assertions.assertEquals(
				Set.of(new BypassedFinding("AWS Access Key", "src/config/app.yml"),
						new BypassedFinding("GitHub Token", "scripts/deploy.sh")),
				found.getFindings());
	}

	@Test
	public void testLongFilePathAndReasonFitColumns() {
		String path = "a/".repeat(500) + "x.yml";
		String reason = "r".repeat(PullRequestBypassEntity.MAX_REASON_LENGTH);

		PullRequestBypassEntity bypass = bypass("pr-1", 1L,
				Set.of(new BypassedFinding("Rule", path)));
		bypass.setReason(reason);
		long id = save(bypass);

		PullRequestBypassEntity found = reload(id);
		Assertions.assertEquals(reason, found.getReason());
		Assertions.assertEquals(path, found.getFindings().iterator().next().getFilePath());
	}

	@Test
	public void testRevokeRoundTrips() {
		PullRequestBypassEntity bypass = bypass("pr-1", 1L, Set.of());
		bypass.revoke("bob", 2000L);
		long id = save(bypass);

		PullRequestBypassEntity found = reload(id);
		Assertions.assertTrue(found.isRevoked());
		Assertions.assertEquals("bob", found.getRevokedBy());
		Assertions.assertEquals(2000L, found.getRevokedAt());
	}

	@Test
	public void testFindActiveSkipsRevokedAndOtherPrs() {
		long active = save(bypass("pr-1", 1L, Set.of()));
		PullRequestBypassEntity revoked = bypass("pr-1", 2L, Set.of());
		revoked.revoke("bob", 2000L);
		save(revoked);
		save(bypass("pr-2", 3L, Set.of()));
		entityManager.clear();

		List<PullRequestBypassEntity> found = bypassRepository.findActive(API_LABEL, REPO, "pr-1");

		Assertions.assertEquals(List.of(active),
				found.stream().map(PullRequestBypassEntity::getId).toList());
	}

	@Test
	public void testFindActiveNewestFirst() {
		PullRequestBypassEntity older = bypass("pr-1", 1L, Set.of());
		older.setCreatedAt(1000L);
		long olderId = save(older);
		PullRequestBypassEntity newer = bypass("pr-1", 2L, Set.of());
		newer.setCreatedAt(5000L);
		long newerId = save(newer);
		entityManager.clear();

		List<Long> ids = bypassRepository.findActive(API_LABEL, REPO, "pr-1").stream()
				.map(PullRequestBypassEntity::getId).toList();

		Assertions.assertEquals(List.of(newerId, olderId), ids);
	}

	@Test
	public void testFindAllActiveAcrossPullRequestsNewestFirst() {
		PullRequestBypassEntity older = bypass("pr-1", 1L, Set.of());
		older.setCreatedAt(1000L);
		long olderId = save(older);
		PullRequestBypassEntity newer = bypass("pr-2", 2L, Set.of());
		newer.setCreatedAt(5000L);
		long newerId = save(newer);
		PullRequestBypassEntity revoked = bypass("pr-3", 3L, Set.of());
		revoked.revoke("bob", 6000L);
		save(revoked);
		entityManager.clear();

		List<Long> ids = bypassRepository.findByRevokedAtIsNullOrderByCreatedAtDesc().stream()
				.map(PullRequestBypassEntity::getId).toList();

		Assertions.assertEquals(List.of(newerId, olderId), ids);
	}

	@Test
	public void testRecentIncludesRevokedNewestFirst() {
		PullRequestBypassEntity first = bypass("pr-1", 1L, Set.of());
		first.setCreatedAt(1000L);
		long firstId = save(first);
		PullRequestBypassEntity second = bypass("pr-2", 2L, Set.of());
		second.setCreatedAt(2000L);
		second.revoke("bob", 3000L);
		long secondId = save(second);
		entityManager.clear();

		List<Long> ids = bypassRepository.findTop200ByOrderByCreatedAtDesc().stream()
				.map(PullRequestBypassEntity::getId).toList();

		Assertions.assertEquals(List.of(secondId, firstId), ids);
	}

	@Test
	public void testCountsPerRepositorySinceAGivenTime() {
		saveAt("payments", 5000L);
		saveAt("payments", 6000L);
		saveAt("billing", 7000L);
		saveAt("billing", 100L);
		entityManager.clear();

		List<RepoBypassCount> counts = bypassRepository.countPerRepositorySince(1000L);

		Assertions.assertEquals(List.of(new RepoBypassCount(API_LABEL, "payments", 2),
				new RepoBypassCount(API_LABEL, "billing", 1)), counts);
	}

	private void saveAt(String repo, long createdAt) {
		PullRequestBypassEntity bypass = bypass("pr-" + createdAt, 1L, Set.of());
		bypass.setRepoName(repo);
		bypass.setCreatedAt(createdAt);
		save(bypass);
	}

	@Test
	public void testScanBlockedFlagRoundTrips() {
		PullRequestContainerEntity container = new PullRequestContainerEntity();
		container.setApiLabel(API_LABEL);
		container.setRepoName(REPO);
		container.setPrId("pr-blocked");
		container.setAuthor("author");
		container.setSourceBranch("src");
		container.setDestinationBranch("dst");
		container = containerRepository.save(container);

		PullRequestScanEntity scan = new PullRequestScanEntity();
		scan.setContainer(container);
		scan.setSubmitDate(System.currentTimeMillis());
		scan.setStatus(ScanStatus.DONE);
		scan.setBlocked(true);
		long scanId = scanRepository.saveAndFlush(scan).getId();
		entityManager.clear();

		Assertions.assertTrue(scanRepository.findById(scanId).isBlocked());
	}

	private PullRequestBypassEntity bypass(String prId, long scanId,
			Set<BypassedFinding> findings) {
		PullRequestBypassEntity bypass = new PullRequestBypassEntity();
		bypass.setApiLabel(API_LABEL);
		bypass.setRepoName(REPO);
		bypass.setPrId(prId);
		bypass.setScanId(scanId);
		bypass.setCommitHash("abc123");
		bypass.setBypassedBy("alice");
		bypass.setReason("Hotfix, accepted risk");
		bypass.setCreatedAt(1000L);
		bypass.setFindings(findings);
		return bypass;
	}

	private long save(PullRequestBypassEntity bypass) {
		return bypassRepository.saveAndFlush(bypass).getId();
	}

	private PullRequestBypassEntity reload(long id) {
		entityManager.flush();
		entityManager.clear();
		return bypassRepository.findById(id).orElseThrow();
	}
}
