package com.tracelink.appsec.watchtower.core.rule.draft;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.support.RequestContextUtils;

import com.tracelink.appsec.watchtower.core.mvc.WatchtowerModelAndView;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * Follows a designer's save when the form carried a {@code draft} field. The designers report a saved rule in
 * different ways (a success message on the page, or a flash message before a redirect), so this looks for
 * either. After a save that did not happen, the page keeps showing the draft so the person can try again.
 */
public class RuleDraftSaveInterceptor implements HandlerInterceptor {
	private static final Pattern SAVE_PATH = Pattern.compile("^/designer/([a-z]+)/save$");

	private final RuleDraftSaveHook hook;
	private final RuleDraftService drafts;

	public RuleDraftSaveInterceptor(RuleDraftSaveHook hook, RuleDraftService drafts) {
		this.hook = hook;
		this.drafts = drafts;
	}

	@Override
	public void postHandle(HttpServletRequest request, HttpServletResponse response, Object handler, ModelAndView mav) {
		String draftId = request.getParameter("draft");
		Matcher path = SAVE_PATH.matcher(request.getRequestURI().substring(request.getContextPath().length()));
		Authentication auth = SecurityContextHolder.getContext().getAuthentication();
		if (draftId == null || draftId.isBlank() || !"POST".equals(request.getMethod()) || !path.matches() || auth == null) {
			return;
		}
		String engine = path.group(1);
		if (savedRule(request, mav)) {
			hook.afterSave(engine, draftId, auth.getName(), request.getParameter("name"));
		} else if (mav != null && !mav.getModel().containsKey("draftBanner")) {
			drafts.ownedOpen(draftId, auth.getName()).filter(found -> found.engine().equals(engine)).map(RuleDraftBanner::of)
					.ifPresent(banner -> mav.addObject("draftBanner", banner));
		}
	}

	private static boolean savedRule(HttpServletRequest request, ModelAndView mav) {
		if (mav != null && mav.getModel().containsKey(WatchtowerModelAndView.SUCCESS_NOTIFICATION)) {
			return true;
		}
		var flash = RequestContextUtils.getOutputFlashMap(request);
		return flash != null && flash.containsKey(WatchtowerModelAndView.SUCCESS_NOTIFICATION);
	}
}
