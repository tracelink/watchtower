package com.tracelink.appsec.module.betterleaks.allowlist;

import java.security.Principal;
import java.time.LocalDate;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import com.tracelink.appsec.module.betterleaks.BetterleaksModule;
import com.tracelink.appsec.watchtower.core.mvc.WatchtowerModelAndView;
import com.tracelink.appsec.watchtower.core.scan.code.CodeScanType;
import com.tracelink.appsec.watchtower.core.scan.repository.RepositoryFilter;
import com.tracelink.appsec.watchtower.core.scan.repository.RepositoryService;

/**
 * The Betterleaks allowlist admin page.
 *
 * @author Watchtower
 */
@Controller
@RequestMapping("/betterleaks/allowlist")
@PreAuthorize("hasAuthority('" + BetterleaksModule.ALLOWLIST_PRIVILEGE_NAME + "')")
public class BetterleaksAllowlistController {

	static final String REDIRECT = "redirect:/betterleaks/allowlist";

	/** How many repositories the Repository field suggests at once. */
	private static final int SUGGESTIONS = 8;

	private final BetterleaksAllowlistService allowlistService;

	private final RepositoryService repositoryService;

	public BetterleaksAllowlistController(
			@Autowired BetterleaksAllowlistService allowlistService,
			RepositoryService repositoryService) {
		this.allowlistService = allowlistService;
		this.repositoryService = repositoryService;
	}

	/** One suggestion for the add dialog's searchable Repository field. */
	public record RepositorySuggestion(String name, String project, String status) {
	}

	/**
	 * Code repositories Watchtower knows, in any integration, whose name contains the typed text,
	 * for the add dialog's searchable Repository field (scripts/repo-suggest.js).
	 *
	 * @param q the typed text
	 * @return up to {@value #SUGGESTIONS} repositories, by name
	 */
	@GetMapping(value = "/repositories", produces = "application/json")
	@ResponseBody
	public List<RepositorySuggestion> repositories(@RequestParam(defaultValue = "") String q) {
		RepositoryFilter filter = new RepositoryFilter(StringUtils.left(q.strip(), MAX_PREFILL_LENGTH),
				null, null, null, null, null);
		return repositoryService.list(CodeScanType.PULL_REQUEST, null, filter,
				PageRequest.of(0, SUGGESTIONS, Sort.by("repoName"))).stream()
				.map(repo -> new RepositorySuggestion(repo.getRepoName(), repo.getApiLabel(),
						!repo.isEnabled() ? "Gone" : repo.isScanningPaused() ? "Paused" : "Active"))
				.toList();
	}

	/**
	 * An entry pre-filled from a report finding ("Allowlist…"): one repository, the exact file
	 * and the rule. Only form defaults - nothing is saved until the user adds a reason.
	 *
	 * @param repoName the repository
	 * @param pathGlob the file
	 * @param ruleId   the Betterleaks rule id
	 */
	public record Prefill(String repoName, String pathGlob, String ruleId) {
	}

	private static final int MAX_PREFILL_LENGTH = 1024;

	@GetMapping("")
	public WatchtowerModelAndView getAllowlist(@RequestParam(required = false) String repo,
			@RequestParam(required = false) String path,
			@RequestParam(required = false) String rule) {
		WatchtowerModelAndView mav = new WatchtowerModelAndView("betterleaks/allowlist");
		mav.addObject("entries", allowlistService.getEntries());
		List<String> ruleIds = new ArrayList<>(allowlistService.getKnownRuleIds().stream()
				.sorted().toList());
		if (StringUtils.isNotBlank(repo) || StringUtils.isNotBlank(path)
				|| StringUtils.isNotBlank(rule)) {
			Prefill prefill = new Prefill(prefillValue(repo), prefillValue(path),
					prefillValue(rule));
			if (prefill.ruleId() != null && !ruleIds.contains(prefill.ruleId())) {
				ruleIds.add(prefill.ruleId());
			}
			mav.addObject("prefill", prefill);
		}
		mav.addObject("ruleIds", ruleIds);
		mav.addObject("scopes", Arrays.asList(BetterleaksAllowlistScope.values()));
		mav.addObject("now", System.currentTimeMillis());
		mav.addScriptReference("/scripts/allowlist.js");
		mav.addScriptReference("/scripts/repo-suggest.js");
		return mav;
	}

	@PostMapping("/add")
	public String addEntry(@RequestParam String scope,
			@RequestParam(required = false) String repoName,
			@RequestParam(required = false) String pathGlob,
			@RequestParam(required = false) String ruleId,
			@RequestParam(required = false) String reason,
			@RequestParam(required = false) String expiresOn, Principal principal,
			RedirectAttributes redirectAttributes) {
		try {
			BetterleaksAllowlistRequest request = new BetterleaksAllowlistRequest(
					parseScope(scope), repoName, pathGlob, ruleId, reason,
					parseDate(expiresOn));
			allowlistService.addEntry(request, principal.getName());
			redirectAttributes.addFlashAttribute(WatchtowerModelAndView.SUCCESS_NOTIFICATION,
					"Added the allowlist entry.");
		} catch (IllegalArgumentException e) {
			redirectAttributes.addFlashAttribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,
					e.getMessage());
		}
		return REDIRECT;
	}

	@PostMapping("/delete")
	public String deleteEntry(@RequestParam long id, Principal principal,
			RedirectAttributes redirectAttributes) {
		try {
			allowlistService.deleteEntry(id, principal.getName());
			redirectAttributes.addFlashAttribute(WatchtowerModelAndView.SUCCESS_NOTIFICATION,
					"Deleted the allowlist entry.");
		} catch (IllegalArgumentException e) {
			redirectAttributes.addFlashAttribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,
					e.getMessage());
		}
		return REDIRECT;
	}

	/** Unknown values are reported without echoing the submitted text. */
	/**
	 * @return the trimmed value, capped in length, or null if blank. The add form's own
	 *         validation decides whether it is acceptable.
	 */
	private static String prefillValue(String value) {
		return StringUtils.left(StringUtils.trimToNull(value), MAX_PREFILL_LENGTH);
	}

	private static BetterleaksAllowlistScope parseScope(String scope) {
		return Arrays.stream(BetterleaksAllowlistScope.values())
				.filter(candidate -> candidate.name().equals(scope)).findFirst()
				.orElseThrow(() -> new IllegalArgumentException("Choose a valid scope."));
	}

	private static LocalDate parseDate(String date) {
		if (StringUtils.isBlank(date)) {
			return null;
		}
		try {
			return LocalDate.parse(date.trim());
		} catch (DateTimeParseException e) {
			throw new IllegalArgumentException("Enter the expiry as a date (YYYY-MM-DD).");
		}
	}
}
