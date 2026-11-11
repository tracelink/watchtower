package com.tracelink.appsec.watchtower.core.rule.workflow;

import java.util.List;
import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;
import org.springframework.web.util.UriComponentsBuilder;

import com.tracelink.appsec.watchtower.core.auth.model.CorePrivilege;
import com.tracelink.appsec.watchtower.core.exception.rule.RuleNotFoundException;
import com.tracelink.appsec.watchtower.core.mvc.WatchtowerModelAndView;
import com.tracelink.appsec.watchtower.core.rule.RuleException;
import com.tracelink.appsec.watchtower.core.rule.RuleService;

/** Rules → Work: one addressable page listing the rule work that needs a person. */
@Controller
@PreAuthorize("hasAuthority('Rule Modify') or hasAuthority('Ruleset View')")
public class RuleWorkController {
	private static final org.slf4j.Logger LOG = org.slf4j.LoggerFactory.getLogger(RuleWorkController.class);
	private final RuleWorkService work;
	private final RuleService rules;

	public RuleWorkController(RuleWorkService work, RuleService rules) {
		this.work = work;
		this.rules = rules;
	}

	@GetMapping("/rules/work")
	public WatchtowerModelAndView work(@RequestParam(required = false) String queue,
			@RequestParam(defaultValue = "") String search, @RequestParam(defaultValue = "") String owner,
			@RequestParam(defaultValue = "false") boolean mine, @RequestParam(defaultValue = "30") int days,
			@RequestParam(defaultValue = "all") String gap, @RequestParam(defaultValue = "all") String scanner,
			@RequestParam(defaultValue = "0") int page, @RequestParam(defaultValue = "25") int pageSize,
			Authentication viewer) {
		boolean canSeeScans = has(viewer, CorePrivilege.SCAN_RESULTS_NAME);
		boolean canModify = has(viewer, CorePrivilege.RULE_MODIFY_NAME);
		// Without scan access the first two lists are empty, so open on reviews instead.
		String selected = queue != null ? queue : canSeeScans ? "review" : "reviews";
		String ownerFilter = mine ? viewer.getName() : owner;
		RuleWorkService.Filter filter;
		try {
			filter = new RuleWorkService.Filter(search, ownerFilter, mine, days, gap, canSeeScans, canModify, scanner);
			RuleWorkService.validate(selected, page, pageSize);
			if (!filter.allScanners() && !work.scanners().containsKey(filter.scanner())) {
				throw new IllegalArgumentException("Unknown scanner");
			}
		} catch (IllegalArgumentException invalid) {
			// Only input validation is the viewer's mistake; query failures stay server errors.
			LOG.info("Rejected rule work filters: {}", invalid.getMessage());
			throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Check the queue, filters, window and page size.");
		}
		var rows = work.queue(selected, filter, page, pageSize);
		var mav = new WatchtowerModelAndView("rules/work");
		mav.addObject("queue", selected);
		mav.addObject("rows", rows);
		mav.addObject("counts", work.counts(filter, selected, rows.totalElements()));
		mav.addObject("filter", filter);
		mav.addObject("mine", mine);
		mav.addObject("canSeeScans", canSeeScans);
		mav.addObject("queues", RuleWorkService.QUEUES);
		mav.addObject("gaps", RuleWorkService.GAPS);
		mav.addObject("windows", RuleWorkService.WINDOWS);
		mav.addObject("scanners", work.scanners());
		mav.addObject("canModify", canModify);
		mav.addObject("maxBulk", RuleService.MAX_BULK_STEWARDSHIP);
		mav.addObject("pageUrl", url(selected, filter, mine, pageSize));
		mav.addScriptReference("/scripts/rule-work.js");
		mav.addScriptReference("/scripts/cwe-starter.js");
		return mav;
	}

	/**
	 * Setup gaps → "Set owner and CWE for selected": one transactional change for the ticked rules,
	 * with the same privilege as the single-rule stewardship form. Returns to the same list.
	 */
	@PostMapping("/rules/work/setup")
	@PreAuthorize("hasAuthority('" + CorePrivilege.RULE_MODIFY_NAME + "')")
	public String setOwnerAndCwe(@RequestParam(name = "ruleId", required = false) List<Long> ruleIds,
			@RequestParam(defaultValue = "") String owner, @RequestParam(defaultValue = "") String cwe,
			@RequestParam(defaultValue = "false") boolean notSecurity,
			@RequestParam(defaultValue = "") String search, @RequestParam(defaultValue = "30") int days,
			@RequestParam(defaultValue = "all") String gap, @RequestParam(defaultValue = "all") String scanner,
			@RequestParam(defaultValue = "25") int pageSize, Authentication viewer, RedirectAttributes redirect) {
		RuleWorkService.Filter back;
		try {
			back = new RuleWorkService.Filter(search, "", false, days, gap, true, true, scanner);
			RuleWorkService.validate("setup", 0, pageSize);
			if (!back.allScanners() && !work.scanners().containsKey(back.scanner())) {
				throw new IllegalArgumentException("Unknown scanner");
			}
		} catch (IllegalArgumentException invalid) {
			throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Check the filters and page size.");
		}
		try {
			int changed = rules.setOwnerAndCwe(ruleIds, owner, cwe, notSecurity, viewer.getName());
			redirect.addFlashAttribute(WatchtowerModelAndView.SUCCESS_NOTIFICATION,
					changed == 1 ? "Saved for 1 rule." : "Saved for " + changed + " rules.");
		} catch (RuleException | RuleNotFoundException refused) {
			redirect.addFlashAttribute(WatchtowerModelAndView.FAILURE_NOTIFICATION, refused.getMessage());
		}
		// The path is fixed. Each option is taken from its known list rather than from the request's own string,
		// and the free text (search) travels as an encoded query parameter, so nothing sent in can change where
		// this goes.
		redirect.addAttribute("queue", pick(RuleWorkService.QUEUES, "setup"));
		redirect.addAttribute("search", back.search());
		redirect.addAttribute("owner", "");
		redirect.addAttribute("mine", false);
		redirect.addAttribute("days", pick(RuleWorkService.WINDOWS, back.days()));
		redirect.addAttribute("gap", pick(RuleWorkService.GAPS, back.gap()));
		redirect.addAttribute("scanner", pick(scannerChoices(), back.scanner()));
		redirect.addAttribute("pageSize", pageSize);
		return "redirect:/rules/work";
	}

	/** The choices for the scanner filter: every scanner, or all of them. */
	private java.util.List<String> scannerChoices() {
		return java.util.stream.Stream.concat(java.util.stream.Stream.of(RuleWorkService.ALL), work.scanners().keySet().stream())
				.toList();
	}

	/** The listed value equal to {@code requested}: what comes back is the list's own, never the request's. */
	private static <T> T pick(java.util.Collection<T> allowed, T requested) {
		return allowed.stream().filter(item -> item.equals(requested)).findFirst()
				.orElseThrow(() -> new ResponseStatusException(HttpStatus.BAD_REQUEST, "Check the filters and page size."));
	}

	/**
	 * One answer for one rule, as chosen in the Suggest CWEs dialog: a CWE, or {@code outcome} "not_security"
	 * for a style or quality rule. An absent outcome means a CWE.
	 */
	public record CweAssignment(Long ruleId, String cwe, String outcome) {
		boolean isNotSecurity() {
			return "not_security".equals(outcome);
		}
	}

	public record CweAssignments(List<CweAssignment> assignments) { }

	/**
	 * Rule work → Suggest CWEs → Apply: gives each chosen rule that still has no CWE the one a person
	 * confirmed. Same privilege and checks as the Setup gaps form, but it answers with counts so the dialog
	 * can say what happened instead of relying on a redirect message.
	 */
	@PostMapping("/rules/work/setup/cwes")
	@PreAuthorize("hasAuthority('" + CorePrivilege.RULE_MODIFY_NAME + "')")
	@org.springframework.web.bind.annotation.ResponseBody
	public org.springframework.http.ResponseEntity<Map<String, Object>> applyCwes(
			@org.springframework.web.bind.annotation.RequestBody CweAssignments body, Authentication viewer) {
		Map<Long, String> chosen = new java.util.LinkedHashMap<>();
		List<Long> notSecurity = new java.util.ArrayList<>();
		java.util.Set<Long> listed = new java.util.HashSet<>();
		for (CweAssignment item : body == null || body.assignments() == null ? List.<CweAssignment>of()
				: body.assignments()) {
			if (item == null || item.ruleId() == null || item.ruleId() <= 0 || !listed.add(item.ruleId())) {
				return org.springframework.http.ResponseEntity.badRequest()
						.body(Map.of("error", "Each rule can be listed once."));
			}
			if (item.isNotSecurity()) {
				notSecurity.add(item.ruleId());
			} else {
				chosen.put(item.ruleId(), item.cwe());
			}
		}
		try {
			int changed = rules.applySuggestions(chosen, notSecurity, viewer.getName());
			return org.springframework.http.ResponseEntity.ok(Map.of("changed", changed, "skipped", listed.size() - changed));
		} catch (RuleException | RuleNotFoundException refused) {
			return org.springframework.http.ResponseEntity.badRequest().body(Map.of("error", refused.getMessage()));
		}
	}

	private static boolean has(Authentication viewer, String privilege) {
		return viewer.getAuthorities().stream().anyMatch(authority -> privilege.equals(authority.getAuthority()));
	}

	/** Template encoding encodes every variable strictly, so "+" in a name or owner survives paging. */
	private static String url(String queue, RuleWorkService.Filter filter, boolean mine, int pageSize) {
		return UriComponentsBuilder.fromPath("/rules/work").queryParam("queue", "{queue}")
				.queryParam("search", "{search}").queryParam("owner", "{owner}").queryParam("mine", "{mine}")
				.queryParam("days", "{days}").queryParam("gap", "{gap}").queryParam("scanner", "{scanner}")
				.queryParam("pageSize", "{pageSize}")
				.encode().buildAndExpand(Map.of("queue", queue, "search", filter.search(),
						"owner", mine ? "" : filter.owner(), "mine", mine, "days", filter.days(), "gap", filter.gap(),
						"scanner", filter.scanner(), "pageSize", pageSize))
				.toUriString();
	}
}
