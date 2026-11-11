package com.tracelink.appsec.watchtower.core.scan.repository;

import java.io.StringReader;
import java.io.StringWriter;
import java.util.List;

import jakarta.persistence.EntityManager;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.transaction.annotation.Transactional;

import com.tracelink.appsec.watchtower.core.WatchtowerTestApplication;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetEntity;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetService;
import com.tracelink.appsec.watchtower.core.scan.ScanStatus;
import com.tracelink.appsec.watchtower.core.scan.code.CodeScanType;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.entity.PlanFrequency;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.entity.RepoScanEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.entity.RepoScanPlanEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.repository.RepoScanPlanRepository;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.repository.RepoScanRepository;
import com.tracelink.appsec.watchtower.core.scan.repository.RepositoryCsvService.ImportResult;

/**
 * Delete and CSV import/export against the real Flyway schema.
 */
@ExtendWith(SpringExtension.class)
@SpringBootTest(classes = WatchtowerTestApplication.class)
@Transactional
public class RepositoryLifecycleTest {

	@Autowired
	private RepositoryService repositories;

	@Autowired
	private RepositoryCsvService csv;

	@Autowired
	private RepositoryRepository repoRepo;

	@Autowired
	private RepoScanPlanRepository planRepo;

	@Autowired
	private RepoScanRepository scanRepo;

	@Autowired
	private RulesetService rulesets;

	@Autowired
	private EntityManager entityManager;

	@BeforeEach
	public void seed() {
		scanRepo.deleteAll();
		repoRepo.deleteAll();
		save("payments-api");
		save("billing");
	}

	@Test
	public void deleteRemovesScanHistoryAndAWebhookAddsTheRepositoryBack() {
		RepositoryEntity repo = repoRepo.findByApiLabelAndRepoName("bb", "payments-api");
		RepoScanPlanEntity plan = new RepoScanPlanEntity();
		plan.setName("p");
		plan.setApiLabel("bb");
		plan.setRepoSelector("*");
		plan.setFrequency(PlanFrequency.ONCE);
		plan.setCreatedBy("test");
		plan = planRepo.save(plan);
		RepoScanEntity scan = new RepoScanEntity();
		scan.setPlanId(plan.getId());
		scan.setRunNo(1);
		scan.setRepository(repo);
		scan.setBranch("main");
		scan.setStatus(ScanStatus.DONE);
		scan.setSubmitDate(1L);
		scanRepo.saveAndFlush(scan);
		repo.setTeam("checkout");
		repo.setScanningPaused(true);
		repoRepo.saveAndFlush(repo);

		RepositoryService.DeleteResult result = repositories.delete(List.of(repo.getId()),
				"alice");
		entityManager.clear();

		Assertions.assertEquals(1, result.deleted());
		Assertions.assertEquals(0, scanRepo.count());
		Assertions.assertNull(repoRepo.findByApiLabelAndRepoName("bb", "payments-api"));
		Assertions.assertNotNull(repoRepo.findByApiLabelAndRepoName("bb", "billing"));

		RepositoryEntity back = repositories.upsertRepo(CodeScanType.PULL_REQUEST, "bb",
				"payments-api");
		RulesetEntity defaultRuleset = rulesets.getDefaultRuleset();
		Assertions.assertNull(back.getTeam());
		Assertions.assertFalse(back.isScanningPaused());
		Assertions.assertEquals(defaultRuleset == null ? null : defaultRuleset.getId(),
				back.getRuleset() == null ? null : back.getRuleset().getId());
	}

	@Test
	public void importSetsProfilesAndReportsBadRows() throws Exception {
		String file = "repo,team,owner,labels,criticality,project,status\n"
				+ "payments-api,checkout,alice,PCI sox,Critical,PAY,Active\n"
				+ "billing,'=finance,,,2,,\n"
				+ "missing,x,,,,,\n"
				+ "billing,,,,Urgent,,\n"
				+ "billing,,,not a label!,,,\n";

		ImportResult result = csv.importCsv(CodeScanType.PULL_REQUEST, "bb",
				new StringReader(file), "alice");
		entityManager.clear();

		Assertions.assertEquals(2, result.updated());
		Assertions.assertEquals(3, result.skipped());
		Assertions.assertEquals(3, result.errors().size());
		Assertions.assertTrue(result.errors().get(0).startsWith("Line 4: no repository named"),
				result.errors().get(0));
		RepositoryEntity payments = repoRepo.findByApiLabelAndRepoName("bb", "payments-api");
		Assertions.assertEquals("checkout", payments.getTeam());
		Assertions.assertEquals("alice", payments.getOwnerName());
		Assertions.assertEquals(List.of("pci", "sox"), payments.getLabels());
		Assertions.assertEquals(1, payments.getCriticality());
		RepositoryEntity billing = repoRepo.findByApiLabelAndRepoName("bb", "billing");
		Assertions.assertEquals("=finance", billing.getTeam(),
				"an export's formula guard is dropped on import");
		Assertions.assertEquals(2, billing.getCriticality());
	}

	@Test
	public void exportIsFormulaSafeAndImportsBackUnchanged() throws Exception {
		RepositoryEntity billing = repoRepo.findByApiLabelAndRepoName("bb", "billing");
		billing.setTeam("=HYPERLINK(\"x\")");
		billing.setLabels(List.of("sox"));
		repoRepo.saveAndFlush(billing);

		StringWriter out = new StringWriter();
		csv.export(CodeScanType.PULL_REQUEST, "bb", RepositoryFilter.NONE, out);

		String[] lines = out.toString().split("\r\n");
		Assertions.assertEquals("repo,project,team,owner,labels,criticality,ruleset,status",
				lines[0]);
		Assertions.assertTrue(lines[1].startsWith("\"billing\",\"\",\"'=HYPERLINK(\"\"x\"\")\""),
				lines[1]);

		ImportResult result = csv.importCsv(CodeScanType.PULL_REQUEST, "bb",
				new StringReader(out.toString()), "alice");
		entityManager.clear();
		Assertions.assertEquals(2, result.updated());
		Assertions.assertEquals(0, result.skipped());
		Assertions.assertEquals("=HYPERLINK(\"x\")",
				repoRepo.findByApiLabelAndRepoName("bb", "billing").getTeam());
	}

	@Test
	public void aColumnTheFileDoesNotHaveIsLeftAlone() throws Exception {
		RepositoryEntity billing = repoRepo.findByApiLabelAndRepoName("bb", "billing");
		billing.setTeam("finance");
		billing.setOwnerName("carol");
		billing.setLabels(List.of("sox"));
		repoRepo.saveAndFlush(billing);

		ImportResult result = csv.importCsv(CodeScanType.PULL_REQUEST, "bb",
				new StringReader("repo,owner\nbilling,dave\n"), "alice");
		entityManager.clear();

		Assertions.assertEquals(1, result.updated());
		RepositoryEntity after = repoRepo.findByApiLabelAndRepoName("bb", "billing");
		Assertions.assertEquals("dave", after.getOwnerName());
		Assertions.assertEquals("finance", after.getTeam(), "no team column, team kept");
		Assertions.assertEquals(List.of("sox"), after.getLabels(), "no labels column, kept");
	}

	@Test
	public void pausingManyTouchesOnlyThePauseFlag() {
		RepositoryEntity billing = repoRepo.findByApiLabelAndRepoName("bb", "billing");
		billing.setTeam("finance");
		repoRepo.saveAndFlush(billing);
		Assertions.assertEquals(1, repositories.setPaused(List.of(billing.getId()), true));
		entityManager.clear();
		RepositoryEntity after = repoRepo.findByApiLabelAndRepoName("bb", "billing");
		Assertions.assertTrue(after.isScanningPaused());
		Assertions.assertEquals("finance", after.getTeam());
	}

	@Test
	public void editingManyChangesOnlyWhatIsFilledIn() throws Exception {
		RepositoryEntity billing = repoRepo.findByApiLabelAndRepoName("bb", "billing");
		billing.setOwnerName("carol");
		repoRepo.saveAndFlush(billing);
		List<Long> both = List.of(billing.getId(),
				repoRepo.findByApiLabelAndRepoName("bb", "payments-api").getId());

		Assertions.assertEquals(2, repositories.editMany(both, -1L, "finance", null, null, 2));
		entityManager.clear();

		RepositoryEntity after = repoRepo.findByApiLabelAndRepoName("bb", "billing");
		Assertions.assertNull(after.getRuleset(), "-1 is no ruleset");
		Assertions.assertEquals("finance", after.getTeam());
		Assertions.assertEquals("carol", after.getOwnerName(), "owner was left as is");
		Assertions.assertEquals(2, after.getCriticality());
		Assertions.assertThrows(IllegalArgumentException.class,
				() -> repositories.editMany(both, null, null, null, null, null));
	}

	@Test
	public void onlyAnExportsFormulaGuardIsDropped() {
		Assertions.assertEquals("=sum", RepositoryCsvService.dropFormulaGuard("'=sum"));
		Assertions.assertEquals("'quoted team", RepositoryCsvService.dropFormulaGuard(
				"'quoted team"));
		Assertions.assertEquals("'", RepositoryCsvService.dropFormulaGuard("'"));
	}

	@Test
	public void importRefusesFilesWithoutARepoColumnOrWithTooManyRows() {
		Assertions.assertThrows(IllegalArgumentException.class, () -> csv.importCsv(
				CodeScanType.PULL_REQUEST, "bb", new StringReader("name,team\nx,y\n"), "alice"));
		StringBuilder big = new StringBuilder("repo,team\n");
		for (int i = 0; i <= RepositoryCsvService.MAX_ROWS; i++) {
			big.append("r").append(i).append(",t\n");
		}
		IllegalArgumentException tooMany = Assertions.assertThrows(
				IllegalArgumentException.class, () -> csv.importCsv(CodeScanType.PULL_REQUEST,
						"bb", new StringReader(big.toString()), "alice"));
		Assertions.assertTrue(tooMany.getMessage().contains("5000"), tooMany.getMessage());
		Assertions.assertEquals(2L, repoRepo.count());
	}

	private void save(String name) {
		RepositoryEntity repo = new RepositoryEntity();
		repo.setApiLabel("bb");
		repo.setRepoName(name);
		repo.setScanType(CodeScanType.PULL_REQUEST);
		repo.setEnabled(true);
		repoRepo.saveAndFlush(repo);
	}
}
