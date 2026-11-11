package com.tracelink.appsec.watchtower.core.scan.code.scm.repo;

import java.util.List;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.entity.PlanFrequency;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.entity.RepoScanPlanEntity;

/**
 * How repository scans are named and numbered on the Runs, queue and run pages.
 */
public class RepoScanNamingTest {

	@Test
	public void anUnnamedPlanIsNamedAfterWhatItScans() {
		Assertions.assertEquals("All repositories", RepoScanService.defaultName(List.of("*")));
		Assertions.assertEquals("1 repository", RepoScanService.defaultName(List.of("id:4")));
		Assertions.assertEquals("3 repositories",
				RepoScanService.defaultName(List.of("id:4", "id:5", "ID:6")));
		Assertions.assertEquals("payments-*, label:pci",
				RepoScanService.defaultName(List.of("payments-*", "label:pci")));
	}

	@Test
	public void aOneOffScanIsNumberedByItsPlanAndARecurringRunByItsRun() {
		RepoScanPlanEntity once = plan(57, "payments-api", PlanFrequency.ONCE);
		RepoScanPlanEntity nightly = plan(3, "Nightly sweep", PlanFrequency.DAILY);

		Assertions.assertEquals("Scan #57 · payments-api", once.runLabel(1));
		Assertions.assertEquals("Nightly sweep · run 4", nightly.runLabel(4));
		Assertions.assertEquals("Scan #12 by alice",
				plan(12, "Scan by alice", PlanFrequency.ONCE).runLabel(1),
				"an older scan's default name");
	}

	private static RepoScanPlanEntity plan(long id, String name, PlanFrequency frequency) {
		RepoScanPlanEntity plan = new RepoScanPlanEntity();
		ReflectionTestUtils.setField(plan, "id", id);
		plan.setName(name);
		plan.setFrequency(frequency);
		return plan;
	}
}
