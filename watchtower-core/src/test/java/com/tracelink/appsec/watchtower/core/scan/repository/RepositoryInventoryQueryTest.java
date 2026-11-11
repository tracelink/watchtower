package com.tracelink.appsec.watchtower.core.scan.repository;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.BDDMockito;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.transaction.annotation.Transactional;

import com.tracelink.appsec.watchtower.core.WatchtowerTestApplication;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.ApiIntegrationEntity;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.ApiIntegrationService;
import com.tracelink.appsec.watchtower.core.scan.ScanStatus;
import com.tracelink.appsec.watchtower.core.scan.code.CodeScanType;
import com.tracelink.appsec.watchtower.core.scan.image.ImageScanType;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.entity.PlanFrequency;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.entity.RepoScanEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.entity.RepoScanPlanEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.repository.RepoScanPlanRepository;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.repository.RepoScanRepository;

/**
 * The inventory's filters as queries against the real Flyway schema.
 */
@ExtendWith(SpringExtension.class)
@SpringBootTest(classes = WatchtowerTestApplication.class)
@Transactional
public class RepositoryInventoryQueryTest {

	private static final long NOW = 1_800_000_000_000L;

	private static final long DAY = 86_400_000L;

	@Autowired
	private RepositoryRepository repoRepo;

	@Autowired
	private RepoScanPlanRepository planRepo;

	@Autowired
	private RepoScanRepository scanRepo;

	private RepositoryStatusService statuses;

	@BeforeEach
	public void seed() {
		scanRepo.deleteAll();
		repoRepo.deleteAll();
		ApiIntegrationService integrations = Mockito.mock(ApiIntegrationService.class);
		ApiIntegrationEntity bb = Mockito.mock(ApiIntegrationEntity.class);
		BDDMockito.when(bb.getApiLabel()).thenReturn("bb");
		BDDMockito.when(bb.getScanType()).thenReturn(CodeScanType.PULL_REQUEST);
		ApiIntegrationEntity ecr = Mockito.mock(ApiIntegrationEntity.class);
		BDDMockito.when(ecr.getApiLabel()).thenReturn("ecr");
		BDDMockito.when(ecr.getScanType()).thenReturn(ImageScanType.CONTAINER);
		BDDMockito.when(integrations.getAllSettings()).thenReturn(List.of(bb, ecr));
		statuses = new RepositoryStatusService(integrations, 30,
				Clock.fixed(Instant.ofEpochMilli(NOW), ZoneOffset.UTC));

		save("bb", "payments_api", true, false, 0, "checkout", "PAY", List.of("pci"));
		save("bb", "paymentsXapi", true, false, NOW - DAY, null, "PAY", List.of());
		save("bb", "legacy-billing", true, false, NOW - 90 * DAY, "Billing", "BIL",
				List.of("pci", "sox"));
		save("bb", "frozen", true, true, NOW - DAY, null, null, List.of());
		save("bb", "deleted-in-bitbucket", false, true, NOW - DAY, null, null, List.of());
		save("gone-integration", "leftover", true, false, NOW - DAY, null, null, List.of());
	}

	@Test
	public void eachStatusFindsItsRepositories() {
		Assertions.assertEquals(List.of("paymentsXapi", "payments_api"),
				names(null, RepositoryFilter.NONE.withStatus(RepoStatus.ACTIVE)));
		Assertions.assertEquals(List.of("legacy-billing"),
				names(null, RepositoryFilter.NONE.withStatus(RepoStatus.INACTIVE)));
		Assertions.assertEquals(List.of("frozen"),
				names(null, RepositoryFilter.NONE.withStatus(RepoStatus.PAUSED)));
		Assertions.assertEquals(List.of("deleted-in-bitbucket"),
				names(null, RepositoryFilter.NONE.withStatus(RepoStatus.GONE)));
		Assertions.assertEquals(List.of("leftover"),
				names(null, RepositoryFilter.NONE.withStatus(RepoStatus.ORPHANED)));
		Assertions.assertEquals(List.of(),
				names("bb", RepositoryFilter.NONE.withStatus(RepoStatus.ORPHANED)));
	}

	@Test
	public void statusFilterAgreesWithTheChip() {
		for (RepoStatus status : RepoStatus.values()) {
			for (RepositoryEntity repo : repoRepo.findAll(statuses.matching(
					CodeScanType.PULL_REQUEST, null, RepositoryFilter.NONE.withStatus(status)))) {
				Assertions.assertEquals(status, statuses.statusOf(repo), repo.getRepoName());
			}
		}
	}

	@Test
	public void searchMatchesNameLabelTeamAndProject() {
		Assertions.assertEquals(List.of("payments_api"),
				names("bb", RepositoryFilter.of("ments_", "", null)),
				"an underscore is a character, not a wildcard");
		Assertions.assertEquals(List.of("legacy-billing", "payments_api"),
				names("bb", RepositoryFilter.of("label:PCI", "", null)));
		Assertions.assertEquals(List.of("legacy-billing"),
				names("bb", RepositoryFilter.of("team:billing project:bil", "", null)));
		Assertions.assertEquals(List.of("paymentsXapi", "payments_api"),
				names("bb", RepositoryFilter.of("PAY project:pay", "", null)));
		Assertions.assertEquals(List.of(), names("bb", RepositoryFilter.of("label:%", "", null)));
	}

	@Test
	public void coverageFollowsTheLatestFinishedScan() {
		RepoScanPlanEntity plan = new RepoScanPlanEntity();
		plan.setName("p");
		plan.setApiLabel("bb");
		plan.setRepoSelector("*");
		plan.setFrequency(PlanFrequency.ONCE);
		plan.setCreatedBy("test");
		plan = planRepo.save(plan);
		lastScan("payments_api", plan.getId(), NOW - 2 * DAY);
		lastScan("legacy-billing", plan.getId(), NOW - 60 * DAY);

		Assertions.assertEquals(List.of("payments_api"),
				names("bb", RepositoryFilter.of("", "", null, "recent")));
		Assertions.assertEquals(List.of("legacy-billing"),
				names("bb", RepositoryFilter.of("", "", null, "stale")));
		Assertions.assertEquals(List.of("deleted-in-bitbucket", "frozen", "paymentsXapi"),
				names("bb", RepositoryFilter.of("", "", null, "never")));
		// The dashboard counts what is still in a live integration: not gone, not orphaned
		Assertions.assertEquals(4, repoRepo.count(statuses.inScm(CodeScanType.PULL_REQUEST,
				null)));
		Assertions.assertEquals(1, repoRepo.count(statuses.inScm(CodeScanType.PULL_REQUEST,
				RepoCoverage.RECENT)));
		Assertions.assertEquals(2, repoRepo.count(statuses.inScm(CodeScanType.PULL_REQUEST,
				RepoCoverage.NEVER)));
	}

	@Test
	public void aRegistryIntegrationNeverAddsToCodeRepositories() {
		// A code-type row under the registry's name (however it got there) is not in the SCM
		save("ecr", "payments-image", true, false, 0, null, null, List.of());

		Assertions.assertEquals(4, repoRepo.count(statuses.inScm(CodeScanType.PULL_REQUEST,
				null)));
		Assertions.assertEquals(java.util.Set.of("bb"),
				statuses.integrationLabels(CodeScanType.PULL_REQUEST));
	}

	private void lastScan(String repoName, long planId, long endDate) {
		RepositoryEntity repo = repoRepo.findByApiLabelAndRepoName("bb", repoName);
		RepoScanEntity scan = new RepoScanEntity();
		scan.setPlanId(planId);
		scan.setRunNo(1);
		scan.setRepository(repo);
		scan.setBranch("main");
		scan.setStatus(ScanStatus.DONE);
		scan.setSubmitDate(endDate - 1000);
		scan.setEndDate(endDate);
		scan = scanRepo.save(scan);
		repo.setLastRepoScanId(scan.getId());
		repoRepo.save(repo);
	}

	private List<String> names(String apiLabel, RepositoryFilter filter) {
		return repoRepo.findAll(statuses.matching(CodeScanType.PULL_REQUEST, apiLabel, filter))
				.stream().map(RepositoryEntity::getRepoName).sorted().toList();
	}

	private void save(String apiLabel, String name, boolean enabled, boolean paused, long lastPr,
			String team, String project, List<String> labels) {
		RepositoryEntity repo = new RepositoryEntity();
		repo.setApiLabel(apiLabel);
		repo.setRepoName(name);
		repo.setScanType(CodeScanType.PULL_REQUEST);
		repo.setEnabled(enabled);
		repo.setScanningPaused(paused);
		repo.setLastReviewedDate(lastPr);
		repo.setTeam(team);
		repo.setProjectKey(project);
		repo.setLabels(labels);
		repoRepo.save(repo);
	}
}
