package com.tracelink.appsec.watchtower.core.rule.draft;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.Optional;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.servlet.FlashMap;
import org.springframework.web.servlet.ModelAndView;

import com.tracelink.appsec.watchtower.core.module.designer.RuleDraftData;
import com.tracelink.appsec.watchtower.core.mvc.WatchtowerModelAndView;
import com.tracelink.appsec.watchtower.core.rule.RuleDto;
import com.tracelink.appsec.watchtower.core.rule.RuleEntity;
import com.tracelink.appsec.watchtower.core.rule.RuleException;
import com.tracelink.appsec.watchtower.core.rule.RuleService;
import com.tracelink.appsec.watchtower.core.rule.RuleState;
import com.tracelink.appsec.watchtower.core.rule.RuleStewardship;
import com.tracelink.appsec.watchtower.core.rule.RuleStewardshipUpdate;

/** After a designer saves a rule opened from a draft: the rule gets its owner and CWE and the draft closes. */
class RuleDraftSaveTest {
	private static final String ID = "5d1c5a0e-0000-4000-8000-000000000001";
	private RuleDraftService drafts;
	private RuleService rules;
	private RuleDraftSaveHook hook;
	private RuleEntity rule;

	private static RuleDraftData draft(String engine, String cwe, String secondary) {
		return new RuleDraftData(ID, engine, null, "No string-built SQL", "m", 2, cwe, secondary, "x+", null, null, null, null, null);
	}

	@BeforeEach
	void setUp() {
		drafts = mock(RuleDraftService.class);
		rules = mock(RuleService.class);
		hook = new RuleDraftSaveHook(drafts, rules);
		rule = mock(RuleEntity.class);
		RuleDto dto = mock(RuleDto.class);
		when(dto.getModule()).thenReturn("regex");
		when(rule.toDto()).thenReturn(dto);
		when(rule.getId()).thenReturn(42L);
		when(rule.getName()).thenReturn("No string-built SQL");
		RuleStewardship stewardship = new RuleStewardship();
		stewardship.setState(RuleState.ACTIVE);
		when(rule.getStewardship()).thenReturn(stewardship);
		when(rules.getRule("No string-built SQL")).thenReturn(rule);
	}

	@AfterEach
	void clear() {
		SecurityContextHolder.clearContext();
	}

	@Test
	void theSavedRuleGetsItsOwnerAndTheDraftsCwesAndTheDraftCloses() throws Exception {
		when(drafts.ownedOpen(ID, "alice")).thenReturn(Optional.of(draft("regex", "CWE-89", "CWE-564")));

		var applied = hook.afterSave("regex", ID, "alice", "No string-built SQL");

		assertThat(applied).contains("No string-built SQL");
		ArgumentCaptor<RuleStewardshipUpdate> update = ArgumentCaptor.forClass(RuleStewardshipUpdate.class);
		verify(rules).updateStewardship(eq(42L), eq("regex"), update.capture(), eq("alice"));
		assertThat(update.getValue().owner()).isEqualTo("alice");
		assertThat(update.getValue().cwe()).isEqualTo("CWE-89");
		assertThat(update.getValue().secondaryCwes()).isEqualTo("CWE-564");
		assertThat(update.getValue().state()).isEqualTo(RuleState.ACTIVE);
		verify(drafts).markUsed(ID, "alice", "No string-built SQL");
	}

	@Test
	void aRegexRuleSavedAsAManualReviewRuleIsFoundUnderItsPrefixedName() {
		when(drafts.ownedOpen(ID, "alice")).thenReturn(Optional.of(draft("regex", "CWE-89", null)));
		when(rules.getRule("No string-built SQL")).thenReturn(null);
		when(rules.getRule("MCR Match: No string-built SQL")).thenReturn(rule);
		when(rule.getName()).thenReturn("MCR Match: No string-built SQL");

		assertThat(hook.afterSave("regex", ID, "alice", "No string-built SQL")).contains("MCR Match: No string-built SQL");
	}

	@Test
	void nothingHappensForAnotherPersonsDraftTheWrongDesignerOrARuleThatIsNotThere() throws Exception {
		when(drafts.ownedOpen(ID, "alice")).thenReturn(Optional.of(draft("regex", "CWE-89", null)));

		assertThat(hook.afterSave("regex", ID, "bob", "No string-built SQL")).isEmpty();
		assertThat(hook.afterSave("pmd", ID, "alice", "No string-built SQL")).isEmpty();
		assertThat(hook.afterSave("regex", ID, "alice", "A different name")).isEmpty();
		assertThat(hook.afterSave("regex", ID, "alice", null)).isEmpty();
		verify(rules, never()).updateStewardship(anyLong(), any(), any(), any());
		verify(drafts, never()).markUsed(any(), any(), any());
	}

	@Test
	void aRuleOfAnotherScannerWithTheSameNameIsNotTouched() throws Exception {
		when(drafts.ownedOpen(ID, "alice")).thenReturn(Optional.of(draft("pmd", "CWE-89", null)));

		assertThat(hook.afterSave("pmd", ID, "alice", "No string-built SQL")).isEmpty();
		verify(rules, never()).updateStewardship(anyLong(), any(), any(), any());
	}

	@Test
	void aFailureToApplyIsLoggedNotThrown() throws Exception {
		when(drafts.ownedOpen(ID, "alice")).thenReturn(Optional.of(draft("regex", "CWE-89", null)));
		org.mockito.Mockito.doThrow(new RuleException("bad")).when(rules).updateStewardship(anyLong(), any(), any(), any());

		assertThat(hook.afterSave("regex", ID, "alice", "No string-built SQL")).isEmpty();
		verify(drafts, never()).markUsed(any(), any(), any());
	}

	// The interceptor: which requests it follows, and how it recognises a save that happened.

	private MockHttpServletRequest post(String uri, String draftId) {
		MockHttpServletRequest request = new MockHttpServletRequest("POST", uri);
		if (draftId != null) {
			request.setParameter("draft", draftId);
		}
		request.setParameter("name", "No string-built SQL");
		SecurityContextHolder.getContext().setAuthentication(new UsernamePasswordAuthenticationToken("alice", "x", java.util.List.of()));
		return request;
	}

	@Test
	void aSaveReportedOnThePageIsFollowed() {
		var spyHook = mock(RuleDraftSaveHook.class);
		var interceptor = new RuleDraftSaveInterceptor(spyHook, drafts);
		var mav = new ModelAndView("x");
		mav.addObject(WatchtowerModelAndView.SUCCESS_NOTIFICATION, "Created rule: No string-built SQL");

		interceptor.postHandle(post("/designer/regex/save", ID), new MockHttpServletResponse(), new Object(), mav);

		verify(spyHook).afterSave("regex", ID, "alice", "No string-built SQL");
	}

	@Test
	void aSaveReportedByAFlashMessageBeforeARedirectIsFollowed() {
		var spyHook = mock(RuleDraftSaveHook.class);
		var interceptor = new RuleDraftSaveInterceptor(spyHook, drafts);
		var request = post("/designer/opengrep/save", ID);
		FlashMap flash = new FlashMap();
		flash.put(WatchtowerModelAndView.SUCCESS_NOTIFICATION, "Rule saved");
		request.setAttribute("org.springframework.web.servlet.DispatcherServlet.OUTPUT_FLASH_MAP", flash);

		interceptor.postHandle(request, new MockHttpServletResponse(), new Object(), new ModelAndView("redirect:/designer/opengrep"));

		verify(spyHook).afterSave("opengrep", ID, "alice", "No string-built SQL");
	}

	@Test
	void aFailedSaveKeepsTheDraftOnThePageAndFollowsNothing() {
		var spyHook = mock(RuleDraftSaveHook.class);
		var interceptor = new RuleDraftSaveInterceptor(spyHook, drafts);
		when(drafts.ownedOpen(ID, "alice")).thenReturn(Optional.of(draft("regex", "CWE-89", null)));
		var mav = new ModelAndView("x");
		mav.addObject(WatchtowerModelAndView.FAILURE_NOTIFICATION, "Failed to validate.");

		interceptor.postHandle(post("/designer/regex/save", ID), new MockHttpServletResponse(), new Object(), mav);

		verify(spyHook, never()).afterSave(any(), any(), any(), any());
		assertThat(mav.getModel().get("draftBanner")).isInstanceOf(RuleDraftBanner.class);
	}

	@Test
	void requestsThatAreNotADraftSaveAreIgnored() {
		var spyHook = mock(RuleDraftSaveHook.class);
		var interceptor = new RuleDraftSaveInterceptor(spyHook, drafts);
		var mav = new ModelAndView("x");
		mav.addObject(WatchtowerModelAndView.SUCCESS_NOTIFICATION, "ok");

		interceptor.postHandle(post("/designer/regex/save", null), new MockHttpServletResponse(), new Object(), mav);
		interceptor.postHandle(post("/designer/regex/query", ID), new MockHttpServletResponse(), new Object(), mav);
		interceptor.postHandle(post("/designer/regex/save/extra", ID), new MockHttpServletResponse(), new Object(), mav);
		var get = new MockHttpServletRequest("GET", "/designer/regex/save");
		get.setParameter("draft", ID);
		interceptor.postHandle(get, new MockHttpServletResponse(), new Object(), mav);
		SecurityContextHolder.clearContext();
		var anonymous = new MockHttpServletRequest("POST", "/designer/regex/save");
		anonymous.setParameter("draft", ID);
		interceptor.postHandle(anonymous, new MockHttpServletResponse(), new Object(), mav);

		verify(spyHook, never()).afterSave(any(), any(), any(), any());
	}
}
