package com.tracelink.appsec.watchtower.core.scan.code.scm.repo.plan;

import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.List;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.mockito.BDDMockito;

import com.tracelink.appsec.watchtower.core.scan.code.scm.api.IScmApi;
import com.tracelink.appsec.watchtower.core.scan.code.scm.api.ScmBranch;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.entity.PlanFrequency;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.queue.RepoQueueMessage;
import com.tracelink.appsec.watchtower.core.scan.repository.RepositoryEntity;

public class RepoScanPlanningTest {

	private static final ZoneId UTC = ZoneId.of("UTC");

	private static RepositoryEntity repo(String name, String team, String project,
			int criticality, String... labels) {
		RepositoryEntity repo = new RepositoryEntity();
		repo.setRepoName(name);
		repo.setTeam(team);
		repo.setProjectKey(project);
		repo.setCriticality(criticality);
		repo.setLabels(List.of(labels));
		return repo;
	}

	private final List<RepositoryEntity> repos = List.of(
			repo("payments-api", "checkout", "PAY", 3, "pci"),
			repo("payments-ui", "checkout", "PAY", 1),
			repo("inventory", "stock", "INV", 2, "core"));

	private static List<String> names(List<RepositoryEntity> chosen) {
		return chosen.stream().map(RepositoryEntity::getRepoName).toList();
	}

	@Test
	public void selectorsMatchByLabelTeamProjectAndGlobMostCriticalFirst() {
		Assertions.assertEquals(List.of("payments-api"),
				names(RepoSelector.resolve("label:PCI", repos)));
		Assertions.assertEquals(List.of("payments-ui", "payments-api"),
				names(RepoSelector.resolve("team:Checkout", repos)));
		Assertions.assertEquals(List.of("inventory"),
				names(RepoSelector.resolve("project:inv", repos)));
		Assertions.assertEquals(List.of("payments-ui", "payments-api"),
				names(RepoSelector.resolve("PAYMENTS-*", repos)));
		Assertions.assertEquals(List.of("payments-ui", "inventory", "payments-api"),
				names(RepoSelector.resolve("*", repos)));
		Assertions.assertEquals(List.of("inventory", "payments-api"),
				names(RepoSelector.resolve("label:core\ninventory\npayments-api", repos)));
	}

	@Test
	public void selectorRejectsEmptyAndBadIds() {
		Assertions.assertThrows(IllegalArgumentException.class, () -> RepoSelector.tokens(" \n"));
		Assertions.assertThrows(IllegalArgumentException.class,
				() -> RepoSelector.tokens("id:abc"));
		Assertions.assertEquals("id:3\nid:5", RepoSelector.ofIds(List.of(3L, 5L, 3L)));
	}

	@Test
	public void globTreatsOtherCharactersLiterally() {
		Assertions.assertTrue(RepoSelector.glob("a.b?").test("A.bc"));
		Assertions.assertFalse(RepoSelector.glob("a.b").test("axb"));
	}

	@Test
	public void globStarsMatchAnyRunIncludingNone() {
		Assertions.assertTrue(RepoSelector.glob("pay*-api").test("payments-api"));
		Assertions.assertTrue(RepoSelector.glob("pay*-api").test("pay-api"));
		Assertions.assertTrue(RepoSelector.glob("*").test(""));
		Assertions.assertTrue(RepoSelector.glob("a*b*c").test("aXbYbZc"));
		Assertions.assertFalse(RepoSelector.glob("a*b*c").test("aXbYbZ"));
		Assertions.assertFalse(RepoSelector.glob("a?").test("a"));
		Assertions.assertFalse(RepoSelector.glob("x").test(null));
	}

	@Test
	@Timeout(2)
	public void globCannotBeMadeSlowByManyStars() {
		String pattern = "*a".repeat(30) + "*b";
		Assertions.assertFalse(RepoSelector.glob(pattern).test("a".repeat(5000)));
	}

	@Test
	public void branchesDefaultToTheMainBranchAndExpandPatterns() {
		IScmApi api = BDDMockito.mock(IScmApi.class);
		BDDMockito.when(api.listBranches("repo", "release/", 100)).thenReturn(List.of(
				new ScmBranch("release/2", "h2", 0), new ScmBranch("release/x-old", "h1", 0),
				new ScmBranch("hotfix", "h3", 0)));

		Assertions.assertEquals(List.of("main"),
				BranchSelector.resolve(" ", "main", api, "repo", 5));
		Assertions.assertEquals(List.of(), BranchSelector.resolve("", null, api, "repo", 5));
		Assertions.assertEquals(List.of("develop", "release/2", "release/x-old"),
				BranchSelector.resolve("develop, release/*", "main", api, "repo", 5));
		Assertions.assertEquals(List.of("develop", "release/2"),
				BranchSelector.resolve("develop, release/*", "main", api, "repo", 2));
	}

	@Test
	public void branchSelectorRejectsUnusableNames() {
		Assertions.assertThrows(IllegalArgumentException.class,
				() -> BranchSelector.validate("main, ../x"));
		Assertions.assertThrows(IllegalArgumentException.class,
				() -> BranchSelector.validate("a b"));
		BranchSelector.validate("main, release/*");
	}

	private static long at(int year, int month, int day, int hour) {
		return ZonedDateTime.of(year, month, day, hour, 0, 0, 0, UTC).toInstant().toEpochMilli();
	}

	@Test
	public void schedulesFallStrictlyAfterNow() {
		long friday10 = at(2026, 10, 9, 10);
		Assertions.assertEquals(at(2026, 10, 10, 2),
				PlanSchedule.next(PlanFrequency.DAILY, 2, null, friday10, UTC));
		Assertions.assertEquals(at(2026, 10, 9, 11),
				PlanSchedule.next(PlanFrequency.DAILY, 11, null, friday10, UTC));
		Assertions.assertEquals(at(2026, 10, 12, 3),
				PlanSchedule.next(PlanFrequency.WEEKLY, 3, 1, friday10, UTC));
		Assertions.assertEquals(at(2026, 10, 16, 10),
				PlanSchedule.next(PlanFrequency.WEEKLY, 10, 5, friday10, UTC));
		Assertions.assertEquals(at(2026, 11, 1, 0),
				PlanSchedule.next(PlanFrequency.MONTHLY, 0, 1, friday10, UTC));
		Assertions.assertNull(PlanSchedule.next(PlanFrequency.ONCE, null, null, friday10, UTC));
	}

	@Test
	public void scheduleValuesAreValidated() {
		PlanSchedule.validate(PlanFrequency.ONCE, null, null);
		Assertions.assertThrows(IllegalArgumentException.class,
				() -> PlanSchedule.validate(PlanFrequency.DAILY, 24, null));
		Assertions.assertThrows(IllegalArgumentException.class,
				() -> PlanSchedule.validate(PlanFrequency.WEEKLY, 1, 8));
		Assertions.assertThrows(IllegalArgumentException.class,
				() -> PlanSchedule.validate(PlanFrequency.MONTHLY, 1, 31));
	}

	@Test
	public void queueMessagesRoundTripAndRejectForeignBodies() {
		RepoQueueMessage scan = RepoQueueMessage.scan(42);
		Assertions.assertEquals(scan, RepoQueueMessage.fromJson(scan.toJson()).orElseThrow());
		Assertions.assertTrue(RepoQueueMessage.fromJson("{\"apiLabel\":1}").isEmpty());
		Assertions.assertTrue(RepoQueueMessage.fromJson("not json").isEmpty());
		Assertions.assertTrue(RepoQueueMessage.fromJson("{\"kind\":\"JOB\",\"id\":0}").isEmpty());
	}
}
