package com.tracelink.appsec.watchtower.core.scan.code.scm.pr;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import com.tracelink.appsec.watchtower.core.scan.code.scm.api.IScmApi;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.PRProviderInlineComments.Finding;

class PRProviderInlineCommentsTest {

	private static final String LINK = "https://wt.example/scan/report/latest?apiLabel=bb&repo=r&prId=1";
	private static final String COMMIT = "4539c9115975abcdef";

	private IScmApi api;
	private PullRequest pr;

	@BeforeEach
	void setup() {
		api = mock(IScmApi.class);
		pr = PullRequestTest.buildStandardPR();
		when(api.listComments(any())).thenReturn(List.of());
		when(api.sendInlineComment(any(), anyString(), anyInt(), anyString())).thenReturn(true);
		when(api.updateComment(any(), anyLong(), anyString())).thenReturn(true);
	}

	private static Finding finding(String path, int line, String severity, String title, boolean blocking, boolean bypassed) {
		return new Finding(path, line, severity, title, blocking, bypassed);
	}

	@Test
	void eachFindingGetsOneCommentOnItsFileAndLineWithSeverityTitleAndLink() {
		PRProviderInlineComments.sync(api, pr, List.of(finding("src/A.java", 12, "HIGH", "SQL injection", true, false),
				finding("src/B.java", 3, "LOW", "Information disclosure", false, false)), COMMIT, LINK);

		ArgumentCaptor<String> text = ArgumentCaptor.forClass(String.class);
		verify(api).sendInlineComment(eq(pr), eq("src/A.java"), eq(12), text.capture());
		assertTrue(text.getValue().startsWith("⛔ **High · SQL injection** · blocking · AWS Security Agent"), text.getValue());
		assertTrue(text.getValue().contains("[Details in the Watchtower report](" + LINK + ")"));
		assertTrue(text.getValue().strip().matches("(?s).*_Watchtower · aws ref [0-9a-f]{12}-12_"));
		ArgumentCaptor<String> second = ArgumentCaptor.forClass(String.class);
		verify(api).sendInlineComment(eq(pr), eq("src/B.java"), eq(3), second.capture());
		assertTrue(second.getValue().startsWith("⚠️ **Low · Information disclosure** · not blocking"), second.getValue());
	}

	@Test
	void aBypassedBlockingFindingSaysSo() {
		PRProviderInlineComments.sync(api, pr, List.of(finding("a.java", 1, "HIGH", "SSRF", true, true)), COMMIT, LINK);
		verify(api).sendInlineComment(eq(pr), eq("a.java"), eq(1), startsWith("✅ **High · SSRF** · blocking bypassed"));
	}

	@Test
	void theCommentNeverCarriesAnythingButSeverityTitleAndLink() {
		PRProviderInlineComments.sync(api, pr, List.of(finding("a.java", 1, "MEDIUM", "Path traversal", false, false)), COMMIT, null);
		ArgumentCaptor<String> text = ArgumentCaptor.forClass(String.class);
		verify(api).sendInlineComment(any(), anyString(), anyInt(), text.capture());
		assertFalse(text.getValue().contains("http"), "without a public URL there is no link");
		assertEquals(3, text.getValue().strip().split("\n").length, "heading, blank line, marker");
	}

	@Test
	void aTitleCannotInjectMarkdown() {
		PRProviderInlineComments.sync(api, pr, List.of(finding("a.java", 1, "LOW", "**bold** [x](http://evil) | `code`", false, false)), COMMIT, LINK);
		ArgumentCaptor<String> text = ArgumentCaptor.forClass(String.class);
		verify(api).sendInlineComment(any(), anyString(), anyInt(), text.capture());
		assertFalse(text.getValue().contains("[x](http://evil)"), text.getValue());
		assertTrue(text.getValue().contains("\\[x\\]"));
	}

	@Test
	void anUnchangedCommentIsLeftAloneAndAChangedOneIsEdited() {
		Finding same = finding("a.java", 5, "HIGH", "SSRF", true, false);
		String ref = PRProviderInlineComments.ref(same);
		String posted = PRProviderInlineComments.text(same, ref, LINK);
		when(api.listComments(any())).thenReturn(List.of(new PullRequestComment(9, posted, "a.java", 5)));

		PRProviderInlineComments.sync(api, pr, List.of(same), COMMIT, LINK);
		verify(api, never()).sendInlineComment(any(), anyString(), anyInt(), anyString());
		verify(api, never()).updateComment(any(), anyLong(), anyString());

		Finding nowBypassed = finding("a.java", 5, "HIGH", "SSRF", true, true);
		PRProviderInlineComments.sync(api, pr, List.of(nowBypassed), COMMIT, LINK);
		verify(api).updateComment(eq(pr), eq(9L), contains("blocking bypassed"));
	}

	@Test
	void aFindingTheLatestReviewDoesNotReturnIsNotedAsNotReportedAndLeftAsHistory() {
		Finding old = finding("a.java", 5, "HIGH", "SSRF", true, false);
		String posted = PRProviderInlineComments.text(old, PRProviderInlineComments.ref(old), LINK);
		when(api.listComments(any())).thenReturn(List.of(new PullRequestComment(9, posted, "a.java", 5)));

		PRProviderInlineComments.sync(api, pr, List.of(), COMMIT, LINK);

		ArgumentCaptor<String> text = ArgumentCaptor.forClass(String.class);
		verify(api).updateComment(eq(pr), eq(9L), text.capture());
		assertTrue(text.getValue().contains("no longer reported by the latest AWS review (commit `4539c91`)"), text.getValue());
		assertTrue(text.getValue().contains("SSRF"));
		assertTrue(text.getValue().strip().endsWith(" · not reported_"));

		// A noted comment is history: it is never edited again
		when(api.listComments(any())).thenReturn(List.of(new PullRequestComment(9, text.getValue(), "a.java", 5)));
		clearInvocations(api);
		PRProviderInlineComments.sync(api, pr, List.of(), COMMIT, LINK);
		verify(api, never()).updateComment(any(), anyLong(), anyString());
	}

	@Test
	void onlyWatchtowersAwsCommentsAreEverTouched() {
		when(api.listComments(any())).thenReturn(List.of(
				new PullRequestComment(1, "A reviewer's inline note", "a.java", 1),
				new PullRequestComment(2, "**High · Rule** · blocking\n\n_Watchtower · ref abcdef123456-7_", "a.java", 7),
				new PullRequestComment(3, "PR level _Watchtower · aws ref abcdef123456-7_", null, null)));
		PRProviderInlineComments.sync(api, pr, List.of(), COMMIT, LINK);
		verify(api, never()).updateComment(any(), anyLong(), anyString());
	}

	@Test
	void theWorstFindingsComeFirstAndTheRestAreCountedNotPosted() {
		List<Finding> many = new ArrayList<>();
		many.add(finding("z.java", 1, "LOW", "Minor", false, false));
		for (int i = 0; i < PRProviderInlineComments.MAX_INLINE; i++) {
			many.add(finding("a.java", i + 1, "MEDIUM", "Medium " + i, false, false));
		}
		many.add(finding("b.java", 1, "HIGH", "Serious", true, false));

		int over = PRProviderInlineComments.sync(api, pr, many, COMMIT, LINK);

		assertEquals(2, over);
		verify(api, times(PRProviderInlineComments.MAX_INLINE)).sendInlineComment(any(), anyString(), anyInt(), anyString());
		verify(api).sendInlineComment(eq(pr), eq("b.java"), eq(1), contains("Serious"));
		verify(api, never()).sendInlineComment(any(), eq("z.java"), anyInt(), anyString());
	}

	@Test
	void theSameFindingTwiceIsOneComment() {
		Finding f = finding("a.java", 5, "HIGH", "SSRF", true, false);
		PRProviderInlineComments.sync(api, pr, List.of(f, f), COMMIT, LINK);
		verify(api, times(1)).sendInlineComment(any(), anyString(), anyInt(), anyString());
	}

	@Test
	void ifTheCommentsCannotBeReadNothingIsPostedSoNothingIsDuplicated() {
		when(api.listComments(any())).thenReturn(null);
		assertEquals(0, PRProviderInlineComments.sync(api, pr, List.of(finding("a.java", 1, "HIGH", "SSRF", true, false)), COMMIT, LINK));
		verify(api, never()).sendInlineComment(any(), anyString(), anyInt(), anyString());
	}
}
