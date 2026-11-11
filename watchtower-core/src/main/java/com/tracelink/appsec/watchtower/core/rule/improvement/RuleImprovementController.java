package com.tracelink.appsec.watchtower.core.rule.improvement;

import java.io.IOException;
import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.server.ResponseStatusException;

import com.tracelink.appsec.watchtower.core.assistant.AssistantSettingsService;
import com.tracelink.appsec.watchtower.core.metrics.RuleHealthService;
import com.tracelink.appsec.watchtower.core.mvc.WatchtowerModelAndView;
import com.tracelink.appsec.watchtower.core.rule.RuleDto;
import com.tracelink.appsec.watchtower.core.rule.RuleReviewService;
import com.tracelink.appsec.watchtower.core.rule.workflow.RuleDetailPresentation;
import com.tracelink.appsec.watchtower.core.scan.presentation.ScannerIdentity;

/**
 * Suggest a rule improvement (Improve board, 2026-10-22): the page names the rule with its scanner
 * tile, severity, health and owner, then walks Evidence → Proposal → Save draft. The JSON routes
 * are unchanged; generating is refused when no person has reviewed anything for the rule.
 */
@Controller
@RequestMapping("/rules/{ruleId}/improvements")
@PreAuthorize("hasAuthority('Assistant Use') and hasAuthority('Ruleset View') and hasAuthority('Scan Results View')")
public class RuleImprovementController {
	private static final int HEALTH_DAYS = 90;

	private final RuleImprovementService improvements;
	private final RuleImprovementEvidence evidence;
	private final RuleReviewService rules;
	private final RuleHealthService health;
	private final AssistantSettingsService settings;

	public RuleImprovementController(RuleImprovementService improvements, RuleImprovementEvidence evidence,
			RuleReviewService rules, RuleHealthService health, AssistantSettingsService settings) {
		this.improvements = improvements;
		this.evidence = evidence;
		this.rules = rules;
		this.health = health;
		this.settings = settings;
	}

	@GetMapping
	public WatchtowerModelAndView page(@PathVariable long ruleId, Authentication viewer) {
		evidence.require(viewer.getName());
		RuleDto rule = rules.current(ruleId);
		var view = new WatchtowerModelAndView("rules/improvements")
				.addScriptReference("/scripts/rule-improvements.js");
		view.addObject("improvementRuleId", ruleId);
		view.addObject("rule", rule);
		view.addObject("scanner", ScannerIdentity.of(rule.getModule()));
		view.addObject("ruleName", ScannerIdentity.withoutScannerPrefix(rule.getName()));
		var calculated = health.health(ruleId, rule.getRevision(), HEALTH_DAYS, "all");
		view.addObject("healthChips", RuleDetailPresentation.compactHealthChips(calculated, health.minimumSample()));
		view.addObject("chat", settings.readiness());
		return view;
	}

	@GetMapping("/evidence")
	@ResponseBody
	public Object evidence(@PathVariable long ruleId, @RequestParam(defaultValue = "90") int days,
			@RequestParam(defaultValue = "") String language, Authentication viewer) {
		return evidence.gather(ruleId, days, language, viewer.getName());
	}

	@PostMapping
	@ResponseBody
	public ResponseEntity<?> generate(@PathVariable long ruleId, @RequestBody RuleImprovementService.Generate request,
			Authentication viewer) throws IOException {
		return ResponseEntity.accepted().body(improvements.generate(ruleId, request, viewer.getName()));
	}

	@GetMapping("/{id}")
	@ResponseBody
	public Object proposal(@PathVariable long ruleId, @PathVariable String id, Authentication viewer) {
		return improvements.get(ruleId, id, viewer.getName());
	}

	@PostMapping("/{id}/candidate")
	@ResponseBody
	@PreAuthorize("hasAuthority('Rule Modify')")
	public Object candidate(@PathVariable long ruleId, @PathVariable String id,
			@RequestBody RuleImprovementService.Save save, Authentication viewer) {
		return improvements.save(ruleId, id, save, viewer.getName());
	}

	@ExceptionHandler(IllegalArgumentException.class)
	@ResponseBody
	public ResponseEntity<?> invalid(IllegalArgumentException error) {
		return ResponseEntity.badRequest().body(Map.of("code", "INVALID_INPUT", "error", error.getMessage()));
	}

	@ExceptionHandler(ResponseStatusException.class)
	@ResponseBody
	public ResponseEntity<?> status(ResponseStatusException error) {
		String code = error.getStatusCode().value() == HttpStatus.CONFLICT.value() ? "STALE_STATE" : "UNAVAILABLE";
		String text = error.getReason() == null ? "Proposal unavailable" : error.getReason();
		return ResponseEntity.status(error.getStatusCode()).body(Map.of("code", code, "error", text));
	}
}
