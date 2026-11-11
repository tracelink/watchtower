package com.tracelink.appsec.watchtower.core.cwe;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * The live CWE coverage table on the review reports page, and the controls that shape it: the profile of
 * weaknesses that matter and the decisions about gaps. Anyone who can see rulesets can read; changing the
 * profile or a decision needs Rule Modify (CSRF applies to every POST). Each change answers with the new table.
 */
@RestController
@RequestMapping("/rules/coverage")
public class CweCoverageController {
	private static final int SEARCH_LIMIT = 10, MAX_QUERY = 80;

	private final CweCoverageService coverage;
	private final CweProfileService profile;
	private final CweCatalogService catalog;
	private final CweStarterMapService starter;

	public CweCoverageController(CweCoverageService coverage, CweProfileService profile, CweCatalogService catalog,
			CweStarterMapService starter) {
		this.coverage = coverage;
		this.profile = profile;
		this.catalog = catalog;
		this.starter = starter;
	}

	@GetMapping
	@PreAuthorize("hasAuthority('Ruleset View')")
	public CweCoverageService.Coverage table() {
		return coverage.coverage();
	}

	/** Catalog entries to pick from in the Edit profile dialog. */
	@GetMapping("/search")
	@PreAuthorize("hasAuthority('Ruleset View')")
	public List<Map<String, Object>> search(@RequestParam(defaultValue = "") String q) {
		String query = q.length() > MAX_QUERY ? q.substring(0, MAX_QUERY) : q;
		return catalog.search(query, SEARCH_LIMIT).stream().map(entry -> {
			Map<String, Object> found = new LinkedHashMap<>();
			found.put("cwe", entry.id());
			found.put("label", entry.label());
			found.put("name", entry.name());
			found.put("discouraged", !entry.isMappable());
			return found;
		}).toList();
	}

	@PostMapping("/profile")
	@PreAuthorize("hasAuthority('Rule Modify')")
	public CweCoverageService.Coverage add(@RequestParam String cwe, @RequestParam(defaultValue = "NORMAL") String priority,
			@RequestParam(required = false) String note, Authentication user) {
		profile.add(cwe, priority, note, user.getName());
		return coverage.coverage();
	}

	@PostMapping("/profile/remove")
	@PreAuthorize("hasAuthority('Rule Modify')")
	public CweCoverageService.Coverage remove(@RequestParam String cwe) {
		profile.remove(cwe);
		return coverage.coverage();
	}

	/** Adds MITRE's Top 25 that are not in the profile yet. */
	@PostMapping("/profile/top25")
	@PreAuthorize("hasAuthority('Rule Modify')")
	public Map<String, Object> addTop25(Authentication user) {
		int added = profile.addTop25(user.getName());
		Map<String, Object> answer = new LinkedHashMap<>();
		answer.put("added", added);
		answer.put("coverage", coverage.coverage());
		return answer;
	}

	@PostMapping("/decision")
	@PreAuthorize("hasAuthority('Rule Modify')")
	public CweCoverageService.Coverage decide(@RequestParam String cwe, @RequestParam String language,
			@RequestParam String decision, @RequestParam(required = false) String note, Authentication user) {
		profile.decide(cwe, language, decision, note, user.getName());
		return coverage.coverage();
	}

	@PostMapping("/decision/clear")
	@PreAuthorize("hasAuthority('Rule Modify')")
	public CweCoverageService.Coverage clear(@RequestParam String cwe, @RequestParam String language) {
		profile.clearDecision(cwe, language);
		return coverage.coverage();
	}

	/** Which rules without a CWE the starter map would fill, for the confirmation dialog. */
	@GetMapping("/starter")
	@PreAuthorize("hasAuthority('Rule Modify')")
	public CweStarterMapService.Preview starterPreview() {
		return starter.preview();
	}

	@PostMapping("/starter")
	@PreAuthorize("hasAuthority('Rule Modify')")
	public Map<String, Object> starterApply(Authentication user) {
		Map<String, Object> answer = new LinkedHashMap<>();
		answer.put("changed", starter.apply(user.getName()));
		answer.put("coverage", coverage.coverage());
		return answer;
	}

	/** The messages come from the profile and starter-map services and never repeat the input. */
	@ExceptionHandler(IllegalArgumentException.class)
	public ResponseEntity<Map<String, String>> refused(IllegalArgumentException problem) {
		return ResponseEntity.badRequest().body(Map.of("error", problem.getMessage()));
	}
}
