package com.tracelink.appsec.watchtower.core.mvc;

import java.util.function.Function;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.SmartView;
import org.springframework.web.servlet.View;

import com.tracelink.appsec.watchtower.core.sidebar.SidebarService;

/**
 * The MvcHandler ensures that the sidebar is configured properly for Watchtower ModelAndView
 * requests. This is separate from the WatchtowerModelAndView in order to decrease calls to the
 * sidebar service and ensure the sidebar service is pulled in to the object correctly (i.e.
 * autowired)
 *
 * @author csmith
 */
public class WatchtowerMvcHandler implements HandlerInterceptor {

	/** Session attribute holding the signed-in user's role names for the account menu. */
	static final String ACCOUNT_ROLES = "wtAccountRoles";
	private record AccountRoles(String username, String names) implements java.io.Serializable { }

	private final SidebarService sidebarService;

	private final String appVersion;

	private final Function<String, String> roleNames;

	public WatchtowerMvcHandler(SidebarService sidebarService, String appVersion) {
		this(sidebarService, appVersion, username -> null);
	}

	/**
	 * @param roleNames the role names of a username ("Full System Admin, Default User"), or null;
	 *                  looked up once per session for the account menu
	 */
	public WatchtowerMvcHandler(SidebarService sidebarService, String appVersion,
			Function<String, String> roleNames) {
		this.sidebarService = sidebarService;
		this.appVersion = appVersion;
		this.roleNames = roleNames;
	}

	@Override
	public void postHandle(HttpServletRequest request, HttpServletResponse response, Object handler,
			ModelAndView modelAndView) throws Exception {

		if (modelAndView != null && !isRedirectView(modelAndView)) {
			modelAndView.addObject("appVersion", appVersion);

			if (isWatchtowerContainerView(modelAndView)) {
				modelAndView.addObject("sidebar", sidebarService.getMenuGroups());
				modelAndView.addObject("breadcrumbLinks",
						sidebarService.getBreadcrumbLinksForPath(request.getRequestURI()));
				modelAndView.addObject("accountRoles", accountRoles(request));
			}
		}
	}

	/**
	 * The account menu's role line. Read once per session (roles rarely change; a new sign-in shows
	 * a change), so page views don't each query the user.
	 */
	private String accountRoles(HttpServletRequest request) {
		HttpSession session = request.getSession(false);
		if (session == null || request.getUserPrincipal() == null) {
			return null;
		}
		String username = request.getUserPrincipal().getName();
		Object cached = session.getAttribute(ACCOUNT_ROLES);
		if (cached instanceof AccountRoles roles && roles.username().equals(username)) {
			return roles.names();
		}
		String roles;
		try {
			roles = roleNames.apply(username);
		} catch (RuntimeException unavailable) {
			// The menu works without the role line; try again on the next page.
			return null;
		}
		roles = roles == null || roles.isBlank() ? null : roles;
		session.setAttribute(ACCOUNT_ROLES, new AccountRoles(username, roles));
		return roles;
	}

	/**
	 * We will only add the sidebar if this {@link ModelAndView} is a {@link WatchtowerModelAndView}
	 * and needs to use the "well-view" mechanism
	 *
	 * @param mv the {@link ModelAndView}
	 * @return true if this is a {@link WatchtowerModelAndView} that needs to use the "well-view"
	 *         mechanism
	 */
	private static boolean isWatchtowerContainerView(ModelAndView mv) {
		return WatchtowerModelAndView.DEFAULT_VIEW_TEMPLATE.equals(mv.getViewName())
				&& mv.getModelMap().containsKey(WatchtowerModelAndView.CONTENT_VIEW_NAME);
	}

	/**
	 * On redirections, we don't need to call the sidebar yet, only on the redirected page's
	 * response, potentially. Also used to keep {@code appVersion} off of redirect responses,
	 * since any model attribute added here would otherwise be appended to the redirect URL as a
	 * query parameter by {@link org.springframework.web.servlet.view.RedirectView}.
	 *
	 * <p>
	 * Most redirects in this codebase are returned as a {@code "redirect:/path"} view-name
	 * {@link String} (resolved to an actual {@link View} later, after {@code postHandle} runs),
	 * rather than as a literal {@link View} instance, so both forms must be checked here.
	 *
	 * @param mv the {@link ModelAndView}
	 * @return true if this seems to be a redirect call, false otherwise
	 */
	private static boolean isRedirectView(ModelAndView mv) {
		String viewName = mv.getViewName();
		if (viewName != null && viewName.startsWith("redirect:")) {
			return true;
		}
		View view = mv.getView();
		return (view instanceof SmartView && ((SmartView) view).isRedirectView());
	}

}
