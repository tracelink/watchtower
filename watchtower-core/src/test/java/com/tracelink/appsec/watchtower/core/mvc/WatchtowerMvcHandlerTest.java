package com.tracelink.appsec.watchtower.core.mvc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Collections;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.mockito.BDDMockito;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.view.RedirectView;

import com.tracelink.appsec.watchtower.core.sidebar.SidebarService;
import com.tracelink.appsec.watchtower.core.sidebar.BreadcrumbLink;

public class WatchtowerMvcHandlerTest {
	@Test
	public void accountRoleLookupIsCachedForEachSignedInUser() throws Exception {
		var lookups = new java.util.ArrayList<String>();
		var mvcHandler = new WatchtowerMvcHandler(mockSidebarService, "local", username -> {
			lookups.add(username);
			return username.equals("alice") ? "Reviewers" : "Operators";
		});
		var request = new MockHttpServletRequest();
		request.getSession();
		request.setUserPrincipal(() -> "alice");
		for (int i = 0; i < 2; i++) {
			var view = new WatchtowerModelAndView("someContent");
			mvcHandler.postHandle(request, new MockHttpServletResponse(), new Object(), view);
			assertEquals("Reviewers", view.getModel().get("accountRoles"));
		}
		assertEquals(List.of("alice"), lookups);
		request.setUserPrincipal(() -> "bob");
		var view = new WatchtowerModelAndView("someContent");
		mvcHandler.postHandle(request, new MockHttpServletResponse(), new Object(), view);
		assertEquals("Operators", view.getModel().get("accountRoles"));
		assertEquals(List.of("alice", "bob"), lookups);
	}

	@Test
	public void roleLookupFailureDoesNotBreakThePageAndCanRetry() throws Exception {
		var lookup = new java.util.concurrent.atomic.AtomicInteger();
		var mvcHandler = new WatchtowerMvcHandler(mockSidebarService, "local", username -> {
			if (lookup.incrementAndGet() == 1) throw new IllegalStateException("unavailable");
			return "Reviewers";
		});
		var request = new MockHttpServletRequest();
		request.getSession();
		request.setUserPrincipal(() -> "alice");
		var view = new WatchtowerModelAndView("someContent");
		mvcHandler.postHandle(request, new MockHttpServletResponse(), new Object(), view);
		assertEquals(null, view.getModel().get("accountRoles"));
		mvcHandler.postHandle(request, new MockHttpServletResponse(), new Object(), view);
		assertEquals("Reviewers", view.getModel().get("accountRoles"));
	}

	private final SidebarService mockSidebarService = BDDMockito.mock(SidebarService.class);

	private final WatchtowerMvcHandler handler =
			new WatchtowerMvcHandler(mockSidebarService, "26.1.7");

	@Test
	public void testPostHandleAddsAppVersionToAnyView() throws Exception {
		ModelAndView mav = new ModelAndView("login");

		handler.postHandle(new MockHttpServletRequest(), new MockHttpServletResponse(), new Object(),
				mav);

		assertEquals("26.1.7", mav.getModel().get("appVersion"));
	}

	@Test
	public void testPostHandleAddsSidebarOnlyForContainerView() throws Exception {
		BDDMockito.when(mockSidebarService.getMenuGroups()).thenReturn(Collections.emptyList());

		WatchtowerModelAndView containerMav = new WatchtowerModelAndView("someContent");

		handler.postHandle(new MockHttpServletRequest(), new MockHttpServletResponse(), new Object(),
				containerMav);

		assertEquals("26.1.7", containerMav.getModel().get("appVersion"));
		assertTrue(containerMav.getModel().containsKey("sidebar"));

		ModelAndView loginMav = new ModelAndView("login");

		handler.postHandle(new MockHttpServletRequest(), new MockHttpServletResponse(), new Object(),
				loginMav);

		assertFalse(loginMav.getModel().containsKey("sidebar"));
	}

	@Test
	public void testPostHandleAddsBreadcrumbLinksOnlyForContainerView() throws Exception {
		BDDMockito.when(mockSidebarService.getMenuGroups()).thenReturn(Collections.emptyList());
		List<BreadcrumbLink> links = List.of(
				new BreadcrumbLink("Rules", "/rulesets"));
		BDDMockito.when(mockSidebarService.getBreadcrumbLinksForPath("/rulesets"))
				.thenReturn(links);

		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setRequestURI("/rulesets");

		WatchtowerModelAndView containerMav = new WatchtowerModelAndView("someContent");

		handler.postHandle(request, new MockHttpServletResponse(), new Object(), containerMav);

		assertEquals(links, containerMav.getModel().get("breadcrumbLinks"));

		ModelAndView loginMav = new ModelAndView("login");

		handler.postHandle(request, new MockHttpServletResponse(), new Object(), loginMav);

		assertFalse(loginMav.getModel().containsKey("breadcrumbLinks"));
	}

	@Test
	public void testPostHandleAddsEmptyBreadcrumbLinksWhenPathHasNoAncestors()
			throws Exception {
		BDDMockito.when(mockSidebarService.getMenuGroups()).thenReturn(Collections.emptyList());
		BDDMockito.when(mockSidebarService.getBreadcrumbLinksForPath("/"))
				.thenReturn(Collections.emptyList());

		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setRequestURI("/");

		WatchtowerModelAndView containerMav = new WatchtowerModelAndView("someContent");

		handler.postHandle(request, new MockHttpServletResponse(), new Object(), containerMav);

		assertTrue(containerMav.getModel().containsKey("breadcrumbLinks"));
		assertEquals(Collections.emptyList(), containerMav.getModel().get("breadcrumbLinks"));
	}

	@Test
	public void testPostHandleSkipsRedirectViewInstances() throws Exception {
		ModelAndView redirectMav = new ModelAndView(new RedirectView("/"));

		handler.postHandle(new MockHttpServletRequest(), new MockHttpServletResponse(), new Object(),
				redirectMav);

		assertFalse(redirectMav.getModel().containsKey("appVersion"));
	}

	@Test
	public void testPostHandleSkipsRedirectViewNameStrings() throws Exception {
		// The common case in this codebase: controllers return "redirect:/path" as a plain
		// String, which Spring wraps into a ModelAndView whose getView() is still null (the
		// "redirect:" view name is only resolved into an actual RedirectView later, after
		// postHandle runs). Adding appVersion here would leak into the redirect URL as
		// "?appVersion=..." once RedirectView renders it.
		ModelAndView redirectMav = new ModelAndView("redirect:/rulesets/2/");

		handler.postHandle(new MockHttpServletRequest(), new MockHttpServletResponse(), new Object(),
				redirectMav);

		assertFalse(redirectMav.getModel().containsKey("appVersion"));
	}

}
