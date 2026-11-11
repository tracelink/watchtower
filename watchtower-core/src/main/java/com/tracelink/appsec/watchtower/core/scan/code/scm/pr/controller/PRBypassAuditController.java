package com.tracelink.appsec.watchtower.core.scan.code.scm.pr.controller;

import java.util.List;
import java.util.Set;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

import com.tracelink.appsec.watchtower.core.auth.model.CorePrivilege;
import com.tracelink.appsec.watchtower.core.mvc.WatchtowerModelAndView;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.bypass.BypassRequestStatus;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.bypass.PRBypassAuditService;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.bypass.PRBypassRequestService;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.bypass.PullRequestBypassRequestEntity;

/**
 * The bypass audit page (§4.16): active and recent PR bypasses, bypasses per repository, and
 * bypass requests (§4.17), which approvers can approve or decline from the list.
 *
 * @author Watchtower
 */
@Controller
@PreAuthorize("hasAuthority('" + CorePrivilege.SCAN_RESULTS_NAME + "')")
public class PRBypassAuditController {

	/** The page's views, one table each: recent bypasses, active ones, counts, requests. */
	private static final Set<String> VIEWS = Set.of("all", "active", "repos", "requests");

	private final PRBypassAuditService auditService;

	private final PRBypassRequestService requestService;

	public PRBypassAuditController(@Autowired PRBypassAuditService auditService,
			@Autowired PRBypassRequestService requestService) {
		this.auditService = auditService;
		this.requestService = requestService;
	}

	/**
	 * With no view chosen, the page opens on the requests while any is pending, so an approver
	 * following the sidebar link lands on what needs a decision.
	 */
	@GetMapping("/scan/bypasses")
	public WatchtowerModelAndView getBypasses(
			@RequestParam(name = "view", required = false) String view,
			Authentication authentication) {
		WatchtowerModelAndView mav = new WatchtowerModelAndView("pull_requests/bypasses");
		List<PullRequestBypassRequestEntity> requests = requestService.recentRequests();
		long pendingCount = requests.stream()
				.filter(request -> request.getStatus() == BypassRequestStatus.PENDING)
				.count();
		mav.addObject("audit", auditService.audit());
		mav.addObject("requests", requests);
		mav.addObject("pendingRequestCount", pendingCount);
		mav.addObject("canManageBypass", authentication != null && authentication
				.getAuthorities().stream().map(GrantedAuthority::getAuthority)
				.anyMatch(CorePrivilege.PR_SCAN_BYPASS_NAME::equals));
		mav.addObject("viewer", authentication == null ? null : authentication.getName());
		// Set.of() is null-hostile: contains(null) throws, so check for no view first.
		if (view != null && VIEWS.contains(view)) {
			mav.addObject("view", view);
		} else {
			mav.addObject("view", view == null && pendingCount > 0 ? "requests" : "all");
		}
		return mav;
	}
}
