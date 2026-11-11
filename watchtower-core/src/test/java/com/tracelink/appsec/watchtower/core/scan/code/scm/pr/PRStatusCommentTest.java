package com.tracelink.appsec.watchtower.core.scan.code.scm.pr;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.tracelink.appsec.watchtower.core.scan.code.scm.api.IScmApi;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.PRStatusComment.Phase;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.PRStatusComment.Result;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.PRStatusComment.Status;

class PRStatusCommentTest {

	private static final String COMMIT = "6421747abcdef0123456789";
	private static final String LINK = "https://watchtower.example/scan/report/latest?apiLabel=bb&repo=r&prId=1";

	private IScmApi api;
	private PullRequest pr;

	@BeforeEach
	void setup() {
		api = mock(IScmApi.class);
		pr = PullRequestTest.buildStandardPR();
	}

	private static Status status(Phase phase, boolean remote, Integer local, Integer remoteFindings,
			Map<String, Integer> severity, Result result) {
		return new Status(COMMIT, phase, remote, local, remoteFindings, severity, result, LINK);
	}

	@Test
	void aStartedScanSaysOnlyThatWatchtowerStartedScanning() {
		for (boolean remote : new boolean[] { false, true }) {
			String md = PRStatusComment.toMarkdown(status(Phase.STARTED, remote, null, null, null, null));
			assertTrue(md.startsWith("### 🛡️ Watchtower — started scanning"), md);
			assertTrue(md.contains("commit `6421747` · [View scan](" + LINK + ")"), md);
			assertFalse(md.contains("|"), "no table: " + md);
			assertFalse(md.contains("AWS"), md);
			assertTrue(md.stripTrailing().endsWith(PRStatusComment.MARKER));
		}
	}

	@Test
	void whenLocalChecksFinishWhileAwsRunsTheCommentSaysSoInOneLine() {
		String md = PRStatusComment.toMarkdown(status(Phase.LOCAL_DONE_REMOTE_RUNNING, true, 2, null, null, null));
		assertTrue(md.contains("### 🛡️ Watchtower — scan in progress"), md);
		assertTrue(md.contains("Watchtower's scanners have finished with 2 findings. The AWS Security Agent review is still running"), md);
		assertFalse(md.contains("|"), md);
	}

	@Test
	void aFinishedScanBecomesTheScanSummaryAnyScannerGets() {
		String summary = PRStatusComment.finalSummary(List.of(), List.of(), null, 0, COMMIT, LINK, false, null);
		String md = PRStatusComment.toMarkdown(new Status(COMMIT, Phase.FINISHED, false, 0, null, null, Result.PASSED, LINK, summary));
		assertTrue(md.startsWith("### 🛡️ Watchtower — ✅ No new issues"), md);
		assertTrue(md.contains("[Full report](" + LINK + ")"), md);
		assertTrue(md.stripTrailing().endsWith(PRStatusComment.MARKER), md);
		assertFalse(md.contains("started scanning"), md);
	}

	@Test
	void theAwsResultIsOneLineInTheSummaryAndItsBlockingFindingsBlockTheHeadline() {
		Map<String, Integer> severity = new LinkedHashMap<>();
		severity.put("LOW", 1);
		severity.put("HIGH", 2);
		severity.put("", 4);
		String passed = PRStatusComment.finalSummary(List.of(), List.of(), null, 0, COMMIT, LINK, false,
				new PRStatusComment.Remote(3, severity, 0));
		assertTrue(passed.contains("**AWS Security Agent:** 3 findings (2 High, 1 Low)"), passed);
		assertTrue(passed.contains("New issues, none blocking"), passed);
		assertTrue(passed.contains("No issues from Watchtower's scanners in the changed files."), passed);
		String blocked = PRStatusComment.finalSummary(List.of(), List.of(), null, 0, COMMIT, LINK, false,
				new PRStatusComment.Remote(3, severity, 2));
		assertTrue(blocked.contains("Blocking issues found"), blocked);
		assertTrue(blocked.contains("· 2 blocking"), blocked);
		assertTrue(PRStatusComment.finalSummary(List.of(), List.of(), null, 0, COMMIT, LINK, false,
				new PRStatusComment.Remote(0, Map.of(), 0)).contains("✅ **AWS Security Agent:** no findings"));
		assertTrue(PRStatusComment.finalSummary(List.of(), List.of(), null, 0, COMMIT, LINK, false,
				new PRStatusComment.Remote(null, null, 0)).contains("**AWS Security Agent:** did not finish"));
	}

	private static PRStatusComment.Row row(String priority, String title, String file, int line, boolean blocking) {
		return new PRStatusComment.Row(priority, title, file, line, blocking, false);
	}

	@Test
	void theCommentListsTheTopTenAwsFindingsAndCountsTheRest() {
		List<PRStatusComment.Row> rows = new java.util.ArrayList<>();
		for (int i = 1; i <= 14; i++) {
			rows.add(row("High", "Finding " + i, "src/A" + i + ".java", i, i == 1));
		}
		String md = PRStatusComment.finalSummary(List.of(), List.of(), null, 0, COMMIT, LINK, false,
				new PRStatusComment.Remote(23, Map.of("HIGH", 23), 1, rows));
		assertTrue(md.contains("**AWS findings: top 10 of 23**"), md);
		assertTrue(md.contains("| ⛔ High | Finding 1 | `src/A1.java:1` |"), md);
		assertTrue(md.contains("| ⚠️ High | Finding 10 | `src/A10.java:10` |"), md);
		assertFalse(md.contains("Finding 11"), md);
		assertTrue(md.contains("…and 13 more in the [full report](" + LINK + ")."), md);
	}

	@Test
	void fewAwsFindingsAreAllListedWithoutACountOfTheRest() {
		String md = PRStatusComment.finalSummary(List.of(), List.of(), null, 0, COMMIT, LINK, false,
				new PRStatusComment.Remote(2, Map.of("LOW", 2), 0,
						List.of(row("Low", "Weak hash", "src/B.java", 4, false), row("Low", "Possible secret or credential", null, 0, false))));
		assertTrue(md.contains("**AWS findings**"), md);
		assertTrue(md.contains("| ⚠️ Low | Weak hash | `src/B.java:4` |"), md);
		assertTrue(md.contains("| ⚠️ Low | Possible secret or credential | — |"), md);
		assertFalse(md.contains("more in the"), md);
	}

	@Test
	void anAwsTitleOrPathCannotBreakTheTable() {
		String md = PRStatusComment.finalSummary(List.of(), List.of(), null, 0, COMMIT, LINK, false,
				new PRStatusComment.Remote(1, Map.of(), 0, List.of(row("High", "a | b `c` <x>", "src/with space|.java", 3, false))));
		assertTrue(md.contains("a \\| b \\`c\\` \\<x\\>"), md);
		assertTrue(md.contains("src/with space\\|.java:3"), md);
	}

	@Test
	void aFinishedScanWithoutASummaryIsItsHeadlineAlone() {
		String blocked = PRStatusComment.toMarkdown(status(Phase.FINISHED, false, 2, null, null, Result.BLOCKED));
		assertTrue(blocked.contains("### 🛡️ Watchtower — ⛔ Blocking issues found"), blocked);
		assertFalse(blocked.contains("|"), blocked);
		String passed = PRStatusComment.toMarkdown(status(Phase.FINISHED, true, 0, null, null, Result.PASSED_BY_POLICY));
		assertTrue(passed.contains("— ⚠️ AWS could not finish, passed by policy"), passed);
		assertTrue(PRStatusComment.toMarkdown(status(Phase.FINISHED, true, 0, null, null, Result.INCOMPLETE))
				.contains("— ⚠️ AWS could not finish, marked incomplete"));
		assertTrue(PRStatusComment.toMarkdown(status(Phase.FINISHED, true, 0, null, null, Result.SUPERSEDED))
				.contains("— A newer commit replaced this one"));
	}

	@Test
	void theCommentNeverCarriesAFindingTitleOrFile() {
		String md = PRStatusComment.toMarkdown(status(Phase.FINISHED, true, 5, 3, Map.of("HIGH", 3), Result.BLOCKED));
		assertFalse(md.toLowerCase().contains("sql") || md.contains(".java"), md);
	}

	@Test
	void withoutAPublicUrlThereIsNoLinkButTheCommitStillShows() {
		String md = PRStatusComment.toMarkdown(new Status(COMMIT, Phase.STARTED, false, null, null, null, null, null));
		assertFalse(md.contains("View scan"));
		assertTrue(md.contains("commit `6421747`"));
	}

	@Test
	void theFirstPostCreatesTheCommentAndLaterOnesEditThatSameComment() {
		when(api.listComments(any())).thenReturn(List.of());
		when(api.sendComment(any(), anyString())).thenReturn(true);
		PRStatusComment.post(api, pr, status(Phase.STARTED, false, null, null, null, null));
		verify(api).sendComment(eq(pr), contains(PRStatusComment.MARKER));

		String posted = PRStatusComment.toMarkdown(status(Phase.STARTED, false, null, null, null, null));
		when(api.listComments(any())).thenReturn(List.of(new PullRequestComment(77, posted, null, null)));
		when(api.updateComment(any(), eq(77L), anyString())).thenReturn(true);
		assertTrue(PRStatusComment.post(api, pr, status(Phase.FINISHED, false, 0, null, null, Result.PASSED)));
		verify(api).updateComment(eq(pr), eq(77L), contains("Scan passed"));
		verify(api, times(1)).sendComment(any(), anyString());
	}

	@Test
	void anUnchangedStatusEditsNothing() {
		String same = PRStatusComment.toMarkdown(status(Phase.STARTED, false, null, null, null, null));
		when(api.listComments(any())).thenReturn(List.of(new PullRequestComment(5, same, null, null)));
		assertTrue(PRStatusComment.post(api, pr, status(Phase.STARTED, false, null, null, null, null)));
		verify(api, never()).updateComment(any(), anyLong(), anyString());
		verify(api, never()).sendComment(any(), anyString());
	}

	@Test
	void otherCommentsAndInlineCommentsAreNeverEdited() {
		when(api.listComments(any())).thenReturn(List.of(
				new PullRequestComment(1, "A developer comment", null, null),
				new PullRequestComment(2, "**Finding**\n\n_Watchtower · ref abc-1_", "A.java", 3),
				new PullRequestComment(3, "Summary comment _Watchtower · scan status_ but with text after", null, null)));
		when(api.sendComment(any(), anyString())).thenReturn(true);
		PRStatusComment.post(api, pr, status(Phase.STARTED, false, null, null, null, null));
		verify(api, never()).updateComment(any(), anyLong(), anyString());
		verify(api).sendComment(eq(pr), anyString());
	}

	@Test
	void ifTheCommentsCannotBeReadItDoesNotRiskADuplicate() {
		when(api.listComments(any())).thenReturn(null);
		assertFalse(PRStatusComment.post(api, pr, status(Phase.STARTED, false, null, null, null, null)));
		verify(api, never()).sendComment(any(), anyString());
	}

	@Test
	void aFailureInTheScmNeverEscapesToTheScan() {
		when(api.listComments(any())).thenThrow(new IllegalStateException("scm down"));
		assertFalse(PRStatusComment.post(api, pr, status(Phase.STARTED, false, null, null, null, null)));
	}

	@Test
	void theReportLinkIsStablePerPullRequestAndEncoded() {
		java.util.function.Function<String, String> enc = v -> java.net.URLEncoder.encode(v, java.nio.charset.StandardCharsets.UTF_8);
		assertEquals("https://wt.example/scan/report/latest?apiLabel=" + enc.apply(pr.getApiLabel()) + "&repo="
				+ enc.apply(pr.getRepoName()) + "&prId=" + enc.apply(pr.getPrId()), PRStatusComment.reportLink("https://wt.example/", pr));
		assertNull(PRStatusComment.reportLink(" ", pr));
	}
}
