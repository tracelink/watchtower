package com.tracelink.appsec.watchtower.core.rule.knowledge;

import java.util.List;

import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.util.UriComponentsBuilder;

import com.tracelink.appsec.watchtower.core.auth.model.CorePrivilege;
import com.tracelink.appsec.watchtower.core.cwe.CweCatalogChip;
import com.tracelink.appsec.watchtower.core.cwe.CweCatalogService;
import com.tracelink.appsec.watchtower.core.mvc.PagedResult;
import com.tracelink.appsec.watchtower.core.mvc.WatchtowerModelAndView;

/**
 * Rules → Knowledge (UAT #23): approved and proposed knowledge as a page instead of a dialog,
 * with searchable pickers for the proposal form. Proposing and deciding still post to
 * {@link KnowledgeController}, which keeps the second-person approval rule.
 */
@Controller
public class KnowledgePageController {
	private static final org.slf4j.Logger LOG = org.slf4j.LoggerFactory.getLogger(KnowledgePageController.class);
	private final KnowledgeWorkspace workspace;
	private final CweCatalogService cweCatalog;

	/** Tab label and icon, and the empty state's title and one line for each status. */
	public record StatusLabels(String tab, String icon, String heading, String empty) {
	}

	private static final java.util.Map<String, StatusLabels> LABELS = java.util.Map.of(
			KnowledgeService.APPROVED, new StatusLabels("Approved", "verified", "No approved knowledge yet",
					"Propose a reviewed fact. Once a second person approves it, the AI assistant can cite it."),
			KnowledgeService.PROPOSED, new StatusLabels("Waiting", "hourglass_top", "Nothing is waiting for approval",
					"Proposals wait here until a second person approves or rejects them."),
			KnowledgeService.RETIRED, new StatusLabels("Retired", "archive", "Nothing has been retired",
					"Approved entries that are no longer true are retired with a reason."),
			KnowledgeService.REJECTED, new StatusLabels("Rejected", "block", "No proposals have been rejected",
					"Proposals a second person turned down are kept here."));

	public KnowledgePageController(KnowledgeWorkspace workspace, CweCatalogService cweCatalog) {
		this.workspace = workspace;
		this.cweCatalog = cweCatalog;
	}

	@GetMapping("/rules/knowledge")
	@PreAuthorize("hasAuthority('Ruleset View')")
	public WatchtowerModelAndView page(@RequestParam(defaultValue = KnowledgeService.APPROVED) String status,
			@RequestParam(defaultValue = "") String search, @RequestParam(defaultValue = "0") int page,
			@RequestParam(defaultValue = "25") int pageSize, @RequestParam(required = false) Long ruleId,
			@RequestParam(required = false) String reviewId, Authentication viewer) {
		boolean canModify = has(viewer, CorePrivilege.RULE_MODIFY_NAME);
		boolean canSeeScans = has(viewer, CorePrivilege.SCAN_RESULTS_NAME);
		PagedResult<KnowledgeWorkspace.Entry> entries;
		try {
			entries = workspace.entries(status, search, page, pageSize, viewer.getName(), canSeeScans);
		} catch (IllegalArgumentException invalid) {
			LOG.info("Rejected knowledge filters: {}", invalid.getMessage());
			throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Check the status, search and page size.");
		}
		var mav = new WatchtowerModelAndView("rules/knowledge").addScriptReference("/scripts/knowledge-page.js")
				.addScriptReference("/scripts/cwe-catalog.js");
		mav.addObject("cweCatalog", CweCatalogChip.of(cweCatalog.status()));
		mav.addObject("status", status);
		mav.addObject("statuses", KnowledgeWorkspace.STATUSES);
		mav.addObject("labels", LABELS);
		mav.addObject("entries", entries);
		mav.addObject("counts", workspace.counts(search));
		mav.addObject("search", search);
		mav.addObject("canModify", canModify);
		mav.addObject("canSeeScans", canSeeScans);
		mav.addObject("prefillRule", canModify && ruleId != null ? workspace.rule(ruleId) : null);
		mav.addObject("prefillReview", canModify && reviewId != null ? workspace.acceptedReview(reviewId) : null);
		mav.addObject("pageUrl", UriComponentsBuilder.fromPath("/rules/knowledge").queryParam("status", "{status}")
				.queryParam("search", "{search}").queryParam("pageSize", "{pageSize}").encode()
				.buildAndExpand(status, search, pageSize).toUriString());
		return mav;
	}

	/** Picker choices. Finding judgments come from scans, so they also need Scan Results View. */
	@GetMapping("/rules/knowledge/options/{kind}")
	@PreAuthorize("hasAuthority('Rule Modify')")
	@ResponseBody
	public PagedResult<KnowledgeWorkspace.Option> options(@PathVariable String kind,
			@RequestParam(defaultValue = "") String search, @RequestParam(required = false) List<Long> ruleIds,
			@RequestParam(defaultValue = "0") int page, @RequestParam(defaultValue = "10") int pageSize,
			Authentication viewer) {
		if ("finding_feedback".equals(kind) && !has(viewer, CorePrivilege.SCAN_RESULTS_NAME)) {
			throw new AccessDeniedException("Finding judgments require Scan Results View");
		}
		try {
			return workspace.options(kind, search, ruleIds, page, pageSize);
		} catch (IllegalArgumentException invalid) {
			LOG.info("Rejected knowledge option request: {}", invalid.getMessage());
			throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Check the list, search and page size.");
		}
	}

	private static boolean has(Authentication viewer, String privilege) {
		return viewer.getAuthorities().stream().anyMatch(authority -> privilege.equals(authority.getAuthority()));
	}
}
