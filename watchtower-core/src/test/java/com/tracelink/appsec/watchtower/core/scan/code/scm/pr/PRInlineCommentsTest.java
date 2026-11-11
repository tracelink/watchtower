package com.tracelink.appsec.watchtower.core.scan.code.scm.pr;

import static com.tracelink.appsec.watchtower.core.scan.code.scm.pr.PRScanSummaryTest.finding;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import org.hamcrest.MatcherAssert;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.BDDMockito;

import com.tracelink.appsec.watchtower.core.rule.RulePriority;
import com.tracelink.appsec.watchtower.core.scan.code.scm.api.IScmApi;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.bypass.ActiveBypass;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.entity.PullRequestViolationEntity;

public class PRInlineCommentsTest {

	private static final String COMMIT = "abc1234def";

	private IScmApi api;
	private PullRequest pr;
	private PRInlineComments inline;
	private final List<PullRequestComment> existing = new ArrayList<>();

	@BeforeEach
	public void setup() {
		api = BDDMockito.mock(IScmApi.class);
		pr = new PullRequest("bb");
		BDDMockito.when(api.listComments(pr)).thenReturn(existing);
		BDDMockito.when(api.sendInlineComment(BDDMockito.eq(pr), BDDMockito.anyString(),
				BDDMockito.anyInt(), BDDMockito.anyString())).thenReturn(true);
		inline = new PRInlineComments(api, pr);
	}

	private static PullRequestViolationEntity blocking(String rule, String file, int line) {
		return finding(rule, file, line, RulePriority.HIGH, true, true);
	}

	private String posted(String file, int line) {
		ArgumentCaptor<String> text = ArgumentCaptor.forClass(String.class);
		BDDMockito.verify(api).sendInlineComment(BDDMockito.eq(pr), BDDMockito.eq(file),
				BDDMockito.eq(line), text.capture());
		return text.getValue();
	}

	@Test
	public void testRefIsRuleAndFileHashPlusLine() {
		String ref = PRInlineComments.ref(blocking("AWS Key", "a.yml", 12));

		MatcherAssert.assertThat(ref, Matchers.matchesPattern("[0-9a-f]{12}-12"));
		Assertions.assertEquals(ref.substring(0, 12),
				PRInlineComments.ref(blocking("AWS Key", "a.yml", 99)).substring(0, 12));
		Assertions.assertNotEquals(ref, PRInlineComments.ref(blocking("AWS Key", "b.yml", 12)));
	}

	@Test
	public void testPostsANewFindingOnItsLine() {
		PullRequestViolationEntity v = blocking("AWS Key", "a.yml", 12);

		Assertions.assertEquals(0, inline.sync(List.of(v), null, COMMIT));

		Assertions.assertEquals("⛔ **High · AWS Key** · blocking\n\nGuidance for AWS Key\n\n"
				+ "_Watchtower · ref " + PRInlineComments.ref(v) + "_", posted("a.yml", 12));
	}

	@Test
	public void testNonBlockingAndBypassedLabels() {
		PullRequestViolationEntity low = finding("Generic", "b.yml", 3, RulePriority.LOW, true,
				false);
		PullRequestViolationEntity bypassed = finding("AWS Key", "a.yml", 12, RulePriority.HIGH,
				true, false);
		bypassed.setBypassed(true);

		inline.sync(List.of(low, bypassed),
				new ActiveBypass("alice", "why", 1L, Set.of()), COMMIT);

		MatcherAssert.assertThat(posted("b.yml", 3),
				Matchers.startsWith("⚠️ **Low · Generic** · not blocking\n"));
		MatcherAssert.assertThat(posted("a.yml", 12),
				Matchers.startsWith("✅ **High · AWS Key** · blocking bypassed by alice\n"));
	}

	@Test
	public void testPreExistingFindingsAreNotCommented() {
		inline.sync(List.of(finding("Old", "c.yml", 1, RulePriority.HIGH, false, false)), null,
				COMMIT);

		BDDMockito.verify(api, BDDMockito.never()).sendInlineComment(BDDMockito.any(),
				BDDMockito.any(), BDDMockito.anyInt(), BDDMockito.any());
	}

	@Test
	public void testUnchangedCommentIsKept() {
		PullRequestViolationEntity v = blocking("AWS Key", "a.yml", 12);
		existing.add(new PullRequestComment(7, PRInlineComments.text(v, null), "a.yml", 12));

		inline.sync(List.of(v), null, COMMIT);

		BDDMockito.verify(api, BDDMockito.never()).sendInlineComment(BDDMockito.any(),
				BDDMockito.any(), BDDMockito.anyInt(), BDDMockito.any());
		BDDMockito.verify(api, BDDMockito.never()).updateComment(BDDMockito.any(),
				BDDMockito.anyLong(), BDDMockito.any());
	}

	@Test
	public void testChangedCommentIsEdited() {
		PullRequestViolationEntity v = blocking("AWS Key", "a.yml", 12);
		existing.add(new PullRequestComment(7, "old text\n\n_Watchtower · ref "
				+ PRInlineComments.ref(v) + "_", "a.yml", 12));

		inline.sync(List.of(v), null, COMMIT);

		BDDMockito.verify(api).updateComment(pr, 7, PRInlineComments.text(v, null));
	}

	@Test
	public void testGoneFindingIsMarkedFixed() {
		PullRequestViolationEntity gone = blocking("AWS Key", "a.yml", 12);
		existing.add(new PullRequestComment(7, PRInlineComments.text(gone, null), "a.yml", 12));

		inline.sync(List.of(), null, COMMIT);

		BDDMockito.verify(api).updateComment(pr, 7,
				"✅ **Fixed in `abc1234`** · ~~High · AWS Key~~\n\n_Watchtower · ref "
						+ PRInlineComments.ref(gone) + " · resolved_");
	}

	@Test
	public void testMovedFindingReplacesItsComment() {
		PullRequestViolationEntity before = blocking("AWS Key", "a.yml", 12);
		PullRequestViolationEntity after = blocking("AWS Key", "a.yml", 15);
		existing.add(new PullRequestComment(7, PRInlineComments.text(before, null), "a.yml", 12));

		inline.sync(List.of(after), null, COMMIT);

		BDDMockito.verify(api).deleteComment(pr, 7);
		BDDMockito.verify(api, BDDMockito.never()).updateComment(BDDMockito.any(),
				BDDMockito.anyLong(), BDDMockito.any());
		posted("a.yml", 15);
	}

	@Test
	public void testOtherCommentsAreNeverTouched() {
		PullRequestViolationEntity gone = blocking("AWS Key", "a.yml", 12);
		existing.add(new PullRequestComment(1, "Please fix this", "a.yml", 12));
		existing.add(new PullRequestComment(2, "summary _Watchtower · ref "
				+ PRInlineComments.ref(gone) + "_", null, null));
		existing.add(new PullRequestComment(3, "✅ **Fixed in `0000000`** · ~~x~~\n\n"
				+ "_Watchtower · ref " + PRInlineComments.ref(gone) + " · resolved_", "a.yml", 12));

		inline.sync(List.of(), null, COMMIT);

		BDDMockito.verify(api, BDDMockito.never()).updateComment(BDDMockito.any(),
				BDDMockito.anyLong(), BDDMockito.any());
		BDDMockito.verify(api, BDDMockito.never()).deleteComment(BDDMockito.any(),
				BDDMockito.anyLong());
	}

	@Test
	public void testReappearingFindingGetsANewComment() {
		PullRequestViolationEntity v = blocking("AWS Key", "a.yml", 12);
		existing.add(new PullRequestComment(3, "✅ fixed\n\n_Watchtower · ref "
				+ PRInlineComments.ref(v) + " · resolved_", "a.yml", 12));

		inline.sync(List.of(v), null, COMMIT);

		posted("a.yml", 12);
	}

	@Test
	public void testCapAndFailedPostsAreCounted() {
		List<PullRequestViolationEntity> many = new ArrayList<>();
		for (int i = 0; i < PRInlineComments.MAX_INLINE + 2; i++) {
			many.add(blocking("Key", "f" + i + ".yml", 1));
		}
		BDDMockito.when(api.sendInlineComment(pr, "f0.yml", 1, PRInlineComments.text(many.get(0),
				null))).thenReturn(false);

		Assertions.assertEquals(3, inline.sync(many, null, COMMIT));
		BDDMockito.verify(api, BDDMockito.times(PRInlineComments.MAX_INLINE))
				.sendInlineComment(BDDMockito.eq(pr), BDDMockito.anyString(), BDDMockito.anyInt(),
						BDDMockito.anyString());
	}

	@Test
	public void testCommentsAlreadyOnThePullRequestShrinkWhatMayBePosted() {
		// 160 comments (Watchtower's earlier ones, bypass requests, replies) already exist
		for (int i = 0; i < 160; i++) {
			existing.add(new PullRequestComment(i, "a human comment " + i, null, null));
		}
		List<PullRequestViolationEntity> many = new ArrayList<>();
		for (int i = 0; i < 40; i++) {
			many.add(blocking("Key", "f" + i + ".yml", 1));
		}

		int notInline = inline.sync(many, null, COMMIT);

		// 200 (provider limit) - 25 (kept free) - 160 = 15 may be posted; the rest go to the summary
		int room = PRInlineComments.PROVIDER_COMMENT_LIMIT - PRInlineComments.COMMENT_RESERVE - 160;
		Assertions.assertEquals(40 - room, notInline);
		BDDMockito.verify(api, BDDMockito.times(room)).sendInlineComment(BDDMockito.eq(pr),
				BDDMockito.anyString(), BDDMockito.anyInt(), BDDMockito.anyString());
	}

	@Test
	public void testNothingIsPostedOnceTheReserveIsReached() {
		for (int i = 0; i < 180; i++) {
			existing.add(new PullRequestComment(i, "a human comment " + i, null, null));
		}

		int notInline = inline.sync(List.of(blocking("Key", "a.yml", 1)), null, COMMIT);

		Assertions.assertEquals(1, notInline);
		BDDMockito.verify(api, BDDMockito.never()).sendInlineComment(BDDMockito.any(),
				BDDMockito.anyString(), BDDMockito.anyInt(), BDDMockito.anyString());
	}

	@Test
	public void testBlockingFindingsAreCommentedFirst() {
		List<PullRequestViolationEntity> many = new ArrayList<>();
		for (int i = 0; i < PRInlineComments.MAX_INLINE; i++) {
			many.add(finding("Low", "f" + i + ".yml", 1, RulePriority.LOW, true, false));
		}
		many.add(blocking("Blocker", "z.yml", 9));

		inline.sync(many, null, COMMIT);

		posted("z.yml", 9);
	}

	@Test
	public void testListFailurePostsNothing() {
		BDDMockito.when(api.listComments(pr)).thenReturn(null);

		Assertions.assertEquals(1, inline.sync(List.of(blocking("Key", "a.yml", 1)), null,
				COMMIT));
		BDDMockito.verify(api, BDDMockito.never()).sendInlineComment(BDDMockito.any(),
				BDDMockito.any(), BDDMockito.anyInt(), BDDMockito.any());
	}

	@Test
	public void testDuplicateFindingsOnOneLineGetOneComment() {
		inline.sync(List.of(blocking("Key", "a.yml", 1), blocking("Key", "a.yml", 1)), null,
				COMMIT);

		posted("a.yml", 1);
	}
}
