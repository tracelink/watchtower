package com.tracelink.appsec.watchtower.core.scan.repository;

import java.util.List;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.BDDMockito;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.data.domain.Page;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.transaction.annotation.Transactional;

import com.tracelink.appsec.watchtower.core.WatchtowerTestApplication;
import com.tracelink.appsec.watchtower.core.rule.RulePriority;
import com.tracelink.appsec.watchtower.core.scan.ScanStatus;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.ApiIntegrationService;
import com.tracelink.appsec.watchtower.core.scan.code.scm.api.bb.BBCloudIntegrationEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.entity.PullRequestContainerEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.entity.PullRequestScanEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.entity.PullRequestViolationEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.repository.PRContainerRepository;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.repository.PRScanRepository;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.repository.PRViolationRepository;
import com.tracelink.appsec.watchtower.core.scan.code.CodeScanType;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.catalog.RepoCatalogDao;
import com.tracelink.appsec.watchtower.core.scan.repository.RepositoryPullRequestService.PullRequestRow;

/**
 * A repository's pull requests against the real Flyway schema (V058's index included).
 */
@ExtendWith(SpringExtension.class)
@SpringBootTest(classes = WatchtowerTestApplication.class)
@Transactional
public class RepositoryPullRequestServiceTest {

	private static final String LABEL = "prpage";

	@Autowired
	private PRContainerRepository containers;

	@Autowired
	private PRScanRepository scans;

	@Autowired
	private PRViolationRepository violations;

	@Autowired
	private RepoCatalogDao catalog;

	@Autowired
	private RepositoryRepository repositories;

	private ApiIntegrationService integrations;

	private RepositoryPullRequestService service;

	@BeforeEach
	public void setup() {
		integrations = Mockito.mock(ApiIntegrationService.class);
		service = new RepositoryPullRequestService(containers, scans, integrations, catalog);
	}

	@Test
	public void pullRequestsStoredUnderTheDisplayNameShowOnTheSlugsPage() {
		// Before webhooks stored the slug they stored "Payments API"; the sync added the slug
		for (String name : List.of("Payments API", "payments-api")) {
			RepositoryEntity repo = new RepositoryEntity();
			repo.setApiLabel(LABEL);
			repo.setRepoName(name);
			repo.setScanType(CodeScanType.PULL_REQUEST);
			repositories.saveAndFlush(repo);
		}
		container("Payments API", "1", 1_000L, false);
		container("payments-api", "2", 2_000L, false);
		container("payments-api-v2", "3", 3_000L, false);

		Assertions.assertEquals(List.of("2", "1"), service.page(LABEL, "payments-api", 0)
				.map(PullRequestRow::prId).getContent());
	}

	@Test
	public void listsTheRepositorysPullRequestsLastReviewedFirstWithTheirNewestScan() {
		PullRequestContainerEntity older = container("payments-api", "1", 1_000L, true);
		scan(older, 10L, ScanStatus.DONE, false, "rule-a", "MCR Match: auth");
		PullRequestContainerEntity newer = container("payments-api", "2", 2_000L, false);
		scan(newer, 20L, ScanStatus.DONE, true, "rule-a", "rule-b", "rule-c");
		PullRequestScanEntity latest = scan(newer, 30L, ScanStatus.DONE, true, "rule-a",
				"rule-b");
		container("payments-api", "3", 0L, false);
		container("billing", "4", 5_000L, false);
		BBCloudIntegrationEntity bb = new BBCloudIntegrationEntity();
		bb.setWorkspace("acme");
		BDDMockito.when(integrations.findByLabel(LABEL)).thenReturn(bb);

		Page<PullRequestRow> page = service.page(LABEL, "payments-api", 0);

		Assertions.assertEquals(3, page.getTotalElements());
		Assertions.assertEquals(List.of("2", "1", "3"),
				page.map(PullRequestRow::prId).getContent());
		PullRequestRow first = page.getContent().get(0);
		Assertions.assertEquals(latest.getId(), first.scanId(), "the newest scan");
		Assertions.assertEquals(2, first.findings());
		Assertions.assertTrue(first.blocked());
		Assertions.assertFalse(first.resolved());
		Assertions.assertEquals("https://bitbucket.org/acme/payments-api/pull-requests/2",
				first.link());
		PullRequestRow second = page.getContent().get(1);
		Assertions.assertEquals(1, second.findings(), "a manual-review match is not a finding");
		Assertions.assertTrue(second.resolved());
		PullRequestRow neverScanned = page.getContent().get(2);
		Assertions.assertNull(neverScanned.scanId());
		Assertions.assertNull(neverScanned.status());
		Assertions.assertEquals(0, neverScanned.findings());
	}

	@Test
	public void theLastPullRequestIsTheNewestByNumberNotTheLastReviewed() {
		// Dev: #57 was re-reviewed after #58 opened, and the chip said "Last PR #57".
		container("payments-api", "57", 9_000L, true);
		container("payments-api", "58", 2_000L, false);
		container("payments-api", "9", 10_000L, true);

		Assertions.assertEquals("58", service.latest(LABEL, "payments-api").orElseThrow().getPrId(),
				"58 is newer than 57, and 9 is older than both despite sorting after them as text");
		Assertions.assertTrue(service.latest(LABEL, "unknown").isEmpty());
	}

	@Test
	public void scansSubmittedInTheSameMillisecondKeepTheLaterOne() {
		PullRequestContainerEntity pr = container("payments-api", "7", 1_000L, false);
		scan(pr, 10L, ScanStatus.FAILED, false);
		PullRequestScanEntity later = scan(pr, 10L, ScanStatus.DONE, false, "rule-a");

		PullRequestRow row = service.page(LABEL, "payments-api", 0).getContent().get(0);

		Assertions.assertEquals(later.getId(), row.scanId());
		Assertions.assertEquals(ScanStatus.DONE, row.status());
		Assertions.assertEquals(1, row.findings());
	}

	@Test
	public void aRepositoryWithoutPullRequestsOrIntegrationIsEmptyAndHasNoLinks() {
		container("payments-api", "1", 1_000L, false);

		Assertions.assertTrue(service.page(LABEL, "unknown", 0).isEmpty());
		Assertions.assertNull(service.page(LABEL, "payments-api", -3).getContent().get(0)
				.link(), "a deleted integration has no SCM link; a negative page is the first");
	}

	@Test
	public void theWebhookLookupStillFindsItsPullRequest() {
		PullRequestContainerEntity pr = container("payments-api", "9", 1_000L, false);

		Assertions.assertEquals(pr.getId(), containers.findFirstByApiLabelAndRepoNameAndPrIdOrderByIdDesc(
				LABEL, "payments-api", "9").getId());
		Assertions.assertNull(containers.findFirstByApiLabelAndRepoNameAndPrIdOrderByIdDesc(LABEL,
				"payments-api", "10"));
	}

	@Test
	public void duplicateRowsForOnePullRequestNoLongerBreakTheLookup() {
		// Older data holds duplicate rows (V058); a single-result lookup threw on them.
		PullRequestContainerEntity older = container("payments-api", "9", 1_000L, false);
		PullRequestContainerEntity newer = container("payments-api", "9", 2_000L, false);

		Assertions.assertEquals(newer.getId(), containers
				.findFirstByApiLabelAndRepoNameAndPrIdOrderByIdDesc(LABEL, "payments-api", "9")
				.getId());
		Assertions.assertEquals(List.of(older.getId(), newer.getId()), containers
				.findByApiLabelAndRepoNameAndPrId(LABEL, "payments-api", "9").stream()
				.map(PullRequestContainerEntity::getId).sorted().toList());
	}

	private PullRequestContainerEntity container(String repo, String prId, long reviewed,
			boolean resolved) {
		PullRequestContainerEntity pr = new PullRequestContainerEntity();
		pr.setApiLabel(LABEL);
		pr.setRepoName(repo);
		pr.setPrId(prId);
		pr.setAuthor("alice");
		pr.setSourceBranch("feature");
		pr.setDestinationBranch("main");
		pr.setLastReviewedDate(reviewed);
		pr.setResolved(resolved);
		return containers.saveAndFlush(pr);
	}

	private PullRequestScanEntity scan(PullRequestContainerEntity pr, long submitted,
			ScanStatus status, boolean blocked, String... findings) {
		PullRequestScanEntity scan = new PullRequestScanEntity();
		scan.setContainer(pr);
		scan.setSubmitDate(submitted);
		scan.setStatus(status);
		scan.setBlocked(blocked);
		scan = scans.saveAndFlush(scan);
		for (String name : findings) {
			PullRequestViolationEntity v = new PullRequestViolationEntity();
			v.setScan(scan);
			v.setViolationName(name);
			v.setSeverity(RulePriority.HIGH);
			v.setFileName("src/App.java");
			v.setLineNum(1);
			violations.saveAndFlush(v);
		}
		return scan;
	}
}
