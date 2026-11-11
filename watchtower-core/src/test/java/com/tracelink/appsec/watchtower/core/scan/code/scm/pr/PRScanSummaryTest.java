package com.tracelink.appsec.watchtower.core.scan.code.scm.pr;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import org.hamcrest.MatcherAssert;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import com.tracelink.appsec.watchtower.core.rule.RulePriority;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.bypass.ActiveBypass;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.entity.PullRequestViolationEntity;

public class PRScanSummaryTest {

	private static final String LINK = "https://wt.example.invalid/scan/report/latest?x=1";

	static PullRequestViolationEntity finding(String rule, String file, int line,
			RulePriority priority, boolean isNew, boolean blocking) {
		PullRequestViolationEntity v = new PullRequestViolationEntity();
		v.setViolationName(rule);
		v.setFileName(file);
		v.setLineNum(line);
		v.setSeverity(priority);
		v.setNewViolation(isNew);
		v.setBlocking(blocking);
		v.setMessage("Guidance for " + rule);
		return v;
	}

	private static String summary(List<PullRequestViolationEntity> findings) {
		return new PRScanSummary(findings, List.of(), null, 0, "abcdef1234567", LINK)
				.toMarkdown();
	}

	@Test
	public void testBlockingHeadlineCountsAndTable() {
		String md = summary(List.of(
				finding("AWS Access Key", "src/app.yml", 12, RulePriority.HIGH, true, true),
				finding("Generic Key", "src/b.yml", 3, RulePriority.MEDIUM, true, false),
				finding("Old Key", "test/c.json", 9, RulePriority.LOW, false, false)));

		MatcherAssert.assertThat(md, Matchers.startsWith(
				"### 🛡️ Watchtower — ⛔ Blocking issues found\n"));
		MatcherAssert.assertThat(md, Matchers.containsString(
				"**2 new issues (1 blocking)** · 1 pre-existing · commit `abcdef1`"));
		MatcherAssert.assertThat(md, Matchers.containsString(
				"| ⛔ High | AWS Access Key | `src/app.yml:12` |"));
		MatcherAssert.assertThat(md, Matchers.containsString(
				"| ⚠️ Medium | Generic Key | `src/b.yml:3` |"));
		MatcherAssert.assertThat(md, Matchers.containsString("**Pre-existing (1, not blocking)**"));
		MatcherAssert.assertThat(md, Matchers.containsString("| Low | Old Key | `test/c.json:9` |"));
		MatcherAssert.assertThat(md, Matchers.stringContainsInOrder("AWS Access Key",
				"Generic Key", "Pre-existing", "Old Key"));
	}

	@Test
	public void testBlockedSummaryTellsHowToAskForABypass() {
		List<PullRequestViolationEntity> blocked = List.of(
				finding("AWS Access Key", "src/app.yml", 12, RulePriority.HIGH, true, true));

		String md = new PRScanSummary(blocked, List.of(), null, 0, "abc1234", LINK, true)
				.toMarkdown();

		MatcherAssert.assertThat(md, Matchers.containsString(
				"> 💬 To ask for a bypass, comment `/watchtower bypass <reason>`."));
	}

	@Test
	public void testNoBypassHintWhenNotBlockedOrNotRequestable() {
		List<PullRequestViolationEntity> notBlocking = List.of(
				finding("Generic Key", "src/b.yml", 3, RulePriority.MEDIUM, true, false));
		List<PullRequestViolationEntity> blocked = List.of(
				finding("AWS Access Key", "src/app.yml", 12, RulePriority.HIGH, true, true));

		// Not blocked: nothing to bypass.
		MatcherAssert.assertThat(new PRScanSummary(notBlocking, List.of(), null, 0, "abc1234",
				LINK, true).toMarkdown(), Matchers.not(Matchers.containsString("/watchtower")));
		// BLOCK_PR declines the pull request, so a request would only be refused.
		MatcherAssert.assertThat(new PRScanSummary(blocked, List.of(), null, 0, "abc1234",
				LINK, false).toMarkdown(), Matchers.not(Matchers.containsString("/watchtower")));
	}

	@Test
	public void testBlockingRowsComeFirst() {
		String md = summary(List.of(
				finding("Low First", "a.yml", 1, RulePriority.LOW, true, false),
				finding("Blocker", "z.yml", 99, RulePriority.MEDIUM, true, true)));

		MatcherAssert.assertThat(md, Matchers.stringContainsInOrder("Blocker", "Low First"));
	}

	@Test
	public void testNoNewIssuesHeadline() {
		String md = summary(List.of(
				finding("Old Key", "c.json", 9, RulePriority.LOW, false, false)));

		MatcherAssert.assertThat(md, Matchers.startsWith("### 🛡️ Watchtower — ✅ No new issues"));
		MatcherAssert.assertThat(md, Matchers.containsString("**No new issues** · 1 pre-existing"));
	}

	@Test
	public void testCleanScan() {
		String md = summary(List.of());

		MatcherAssert.assertThat(md, Matchers.startsWith("### 🛡️ Watchtower — ✅ No new issues"));
		MatcherAssert.assertThat(md, Matchers.containsString("No issues found in the changed files."));
		MatcherAssert.assertThat(md, Matchers.not(Matchers.containsString("| Priority |")));
	}

	@Test
	public void testNonBlockingHeadline() {
		String md = summary(List.of(
				finding("Generic Key", "b.yml", 3, RulePriority.MEDIUM, true, false)));

		MatcherAssert.assertThat(md, Matchers.startsWith(
				"### 🛡️ Watchtower — ⚠️ New issues, none blocking"));
	}

	@Test
	public void testBypassedHeadlineRowAndNote() {
		PullRequestViolationEntity bypassed =
				finding("AWS Access Key", "a.yml", 12, RulePriority.HIGH, true, false);
		bypassed.setBypassed(true);
		ActiveBypass bypass = new ActiveBypass("alice", "Hotfix\nfor outage", 1L, Set.of());

		String md = new PRScanSummary(List.of(bypassed), List.of(), bypass, 0, "abc1234", LINK)
				.toMarkdown();

		MatcherAssert.assertThat(md, Matchers.startsWith("### 🛡️ Watchtower — ✅ Blocking bypassed"));
		MatcherAssert.assertThat(md, Matchers.containsString("| ✅ High | AWS Access Key |"));
		MatcherAssert.assertThat(md, Matchers.containsString(
				"> ✅ **Blocking bypassed by alice:** `Hotfix for outage`."
						+ " New blocking findings still block."));
	}

	@Test
	public void testIncompleteAndNotInlinedNotes() {
		String md = new PRScanSummary(
				List.of(finding("Key", "a.yml", 1, RulePriority.HIGH, true, true)),
				List.of("Betterleaks"), null, 2, "abc1234", LINK).toMarkdown();

		MatcherAssert.assertThat(md, Matchers.containsString(
				"> ⚠️ **Scan incomplete:** Betterleaks did not finish, so findings may be missing."
						+ " Push again to rescan."));
		MatcherAssert.assertThat(md, Matchers.containsString(
				"> ℹ️ 2 findings could not be commented on their line."));
	}

	@Test
	public void testAnIncompleteScanWithNoFindingsIsNeverReportedAsClean() {
		String md = new PRScanSummary(List.of(), List.of("Json", "EsLint"), null, 0, "abc1234", LINK)
				.toMarkdown();

		MatcherAssert.assertThat(md, Matchers.containsString("⚠️ Scan incomplete"));
		MatcherAssert.assertThat(md, Matchers.not(Matchers.containsString("✅ No new issues")));
		MatcherAssert.assertThat(md, Matchers.not(Matchers.containsString(
				"No issues found in the changed files.")));
		MatcherAssert.assertThat(md, Matchers.containsString("Json, EsLint did not finish"));
	}

	@Test
	public void testACompleteScanWithNoFindingsStillGetsTheCheckMark() {
		MatcherAssert.assertThat(summary(List.of()),
				Matchers.containsString("✅ No new issues"));
	}

	@Test
	public void testFooterLinksTheReport() {
		String md = summary(List.of(finding("Key", "a.yml", 1, RulePriority.HIGH, true, true)));

		MatcherAssert.assertThat(md, Matchers.endsWith("Details are on each line · [Full report]("
				+ LINK + ") · Questions: #security-team · security@example.com"));
	}

	@Test
	public void testFooterWithoutLinkOrNewFindings() {
		String md = new PRScanSummary(List.of(), List.of(), null, 0, null, null).toMarkdown();

		MatcherAssert.assertThat(md, Matchers.endsWith(
				"\nQuestions: #security-team · security@example.com"));
		MatcherAssert.assertThat(md, Matchers.not(Matchers.containsString("commit `")));
	}

	@Test
	public void testRowsAreCappedWithAPointerToTheReport() {
		List<PullRequestViolationEntity> many = new ArrayList<>();
		for (int i = 0; i < PRScanSummary.MAX_ROWS + 3; i++) {
			many.add(finding("Key", "f" + i + ".yml", 1, RulePriority.HIGH, true, true));
		}

		String md = summary(many);

		Assertions.assertEquals(PRScanSummary.MAX_ROWS, md.split("\\| ⛔ High \\|", -1).length - 1);
		MatcherAssert.assertThat(md, Matchers.containsString(
				"…and 3 more in the [full report](" + LINK + ")."));
	}

	@Test
	public void testCellsAreEscaped() {
		String md = summary(List.of(finding("Rule | *x* [y]", "dir/a`b|c.yml", 1,
				RulePriority.HIGH, true, true)));

		MatcherAssert.assertThat(md, Matchers.containsString(
				"| ⛔ High | Rule \\| \\*x\\* \\[y\\] | dir/a\\`b\\|c.yml:1 |"));
	}
}
