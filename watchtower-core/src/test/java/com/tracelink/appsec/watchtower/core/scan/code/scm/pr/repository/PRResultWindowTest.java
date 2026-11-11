package com.tracelink.appsec.watchtower.core.scan.code.scm.pr.repository;

import java.util.List;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.domain.Sort.Direction;
import org.springframework.core.env.Environment;
import org.mockito.Mockito;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.transaction.annotation.Transactional;

import com.tracelink.appsec.watchtower.core.WatchtowerTestApplication;
import com.tracelink.appsec.watchtower.core.exception.ScanRejectedException;
import com.tracelink.appsec.watchtower.core.rule.RulePriority;
import com.tracelink.appsec.watchtower.core.scan.ScanStatus;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.ApiIntegrationEntity;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.ApiIntegrationService;
import com.tracelink.appsec.watchtower.core.scan.code.scm.api.IScmApi;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.entity.PullRequestContainerEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.entity.PullRequestScanEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.entity.PullRequestViolationEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.entity.PullRequestSyncSettingsEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.service.PRScanResultService;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.service.PullRequestSynchronizer;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.service.PullRequestSyncSettingsService;
import com.tracelink.appsec.watchtower.core.scan.repository.RepositoryRepository;

/**
 * The results page's windows against the real Flyway schema (V059's indexes included).
 */
@ExtendWith(SpringExtension.class)
@SpringBootTest(classes = WatchtowerTestApplication.class)
@Transactional
public class PRResultWindowTest {

	private static final long CUTOFF = 1_000_000L;

	private static final Pageable PAGE =
			PageRequest.of(0, 50, Sort.by(Direction.DESC, "endDate").and(Sort.by("id")));

	@Autowired
	private PRContainerRepository containers;

	@Autowired
	private PRScanRepository scans;

	@Autowired
	private PRViolationRepository violations;

	@Autowired
	private PRScanResultService results;

	private PullRequestScanEntity recentClean;

	private PullRequestScanEntity recentWithFindings;

	private PullRequestScanEntity running;

	private PullRequestScanEntity oldWithFindings;

	private PullRequestScanEntity oldOnlyManualReview;

	@BeforeEach
	public void seed() {
		violations.deleteAll();
		scans.deleteAll();
		containers.deleteAll();
		PullRequestContainerEntity pr = new PullRequestContainerEntity();
		pr.setApiLabel("window");
		pr.setRepoName("repo");
		pr.setPrId("1");
		pr.setAuthor("alice");
		pr.setSourceBranch("feature");
		pr = containers.saveAndFlush(pr);
		recentClean = scan(pr, CUTOFF + 10);
		recentWithFindings = scan(pr, CUTOFF, "rule-a");
		running = scan(pr, 0);
		oldWithFindings = scan(pr, CUTOFF - 1, "rule-a");
		oldOnlyManualReview = scan(pr, 5, "MCR Match: auth");
	}

	@Test
	public void theRecentWindowHoldsRunningScansAndTheOlderOneTheRest() {
		Assertions.assertEquals(List.of(recentClean.getId(), recentWithFindings.getId(),
				running.getId()), ids(scans.findEndedSince(CUTOFF, PAGE).getContent()));
		Assertions.assertEquals(List.of(oldWithFindings.getId(), oldOnlyManualReview.getId()),
				ids(scans.findEndedBefore(CUTOFF, PAGE).getContent()));
		Assertions.assertEquals(3, scans.findEndedSince(CUTOFF, PAGE).getTotalElements());
	}

	@Test
	public void withFindingsLeavesOutCleanScansAndManualReviewMatches() {
		Assertions.assertEquals(List.of(recentWithFindings.getId()),
				ids(scans.findWithFindingsEndedSince(CUTOFF, PAGE).getContent()));
		Assertions.assertEquals(List.of(oldWithFindings.getId()),
				ids(scans.findWithFindingsEndedBefore(CUTOFF, PAGE).getContent()));
		Assertions.assertEquals(1, scans.findWithFindingsEndedBefore(CUTOFF, PAGE)
				.getTotalElements());
	}

	@Test
	public void synchronizerClosesEveryOrphanAcrossShrinkingPagesAndPreservesHistory() throws Exception {
		for (int i = 0; i < 205; i++) {
			PullRequestContainerEntity pr = new PullRequestContainerEntity();
			pr.setApiLabel("deleted");
			pr.setRepoName("repo");
			pr.setPrId(Integer.toString(i));
			pr.setAuthor("alice");
			pr.setSourceBranch("feature");
			pr.setDestinationBranch("main");
			containers.save(pr);
		}
		containers.flush();
		ApiIntegrationService integrations = Mockito.mock(ApiIntegrationService.class);
		ApiIntegrationEntity liveIntegration = Mockito.mock(ApiIntegrationEntity.class);
		IScmApi scm = Mockito.mock(IScmApi.class);
		Mockito.when(liveIntegration.createApi()).thenReturn(scm);
		Mockito.when(integrations.findByLabel("window")).thenReturn(liveIntegration);
		Mockito.when(scm.updatePRData(Mockito.any())).thenThrow(new ScanRejectedException("Temporary SCM failure"));
		RepositoryRepository repositories = Mockito.mock(RepositoryRepository.class);
		Mockito.when(repositories.findByLastReviewedDateBefore(Mockito.anyLong())).thenReturn(List.of());
		PullRequestSyncSettingsService settings = Mockito.mock(PullRequestSyncSettingsService.class);
		Mockito.when(settings.getSettings()).thenReturn(new PullRequestSyncSettingsEntity());
		PullRequestSynchronizer synchronizer = new PullRequestSynchronizer(Mockito.mock(Environment.class),
				containers, results, integrations, repositories, settings);

		synchronizer.syncData();

		Assertions.assertEquals(206, containers.count());
		var unresolved = containers.findByResolvedFalse(PageRequest.of(0, 1));
		Assertions.assertEquals(1, unresolved.getTotalElements());
		Assertions.assertEquals("window", unresolved.getContent().getFirst().getApiLabel());
		Mockito.verify(scm).updatePRData(Mockito.any());
		Assertions.assertEquals(5, scans.count());
		Assertions.assertEquals(3, violations.count());
		Mockito.verify(settings).recordSyncCompleted(Mockito.anyLong());
	}

	private static List<Long> ids(List<PullRequestScanEntity> list) {
		return list.stream().map(PullRequestScanEntity::getId).toList();
	}

	private PullRequestScanEntity scan(PullRequestContainerEntity pr, long ended,
			String... findings) {
		PullRequestScanEntity scan = new PullRequestScanEntity();
		scan.setContainer(pr);
		scan.setSubmitDate(Math.max(1, ended - 1));
		scan.setEndDate(ended);
		scan.setStatus(ended == 0 ? ScanStatus.IN_PROGRESS : ScanStatus.DONE);
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
