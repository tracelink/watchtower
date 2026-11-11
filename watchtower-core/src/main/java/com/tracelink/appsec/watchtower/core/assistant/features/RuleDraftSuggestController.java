package com.tracelink.appsec.watchtower.core.assistant.features;

import java.util.Map;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Asks the assistant to draft a rule for a coverage gap. It stores a draft for the person who asked and returns
 * the link to open it in a designer; it saves no rule.
 */
@RestController
@RequestMapping("/assistant")
@PreAuthorize("hasAuthority('Assistant Use')")
public class RuleDraftSuggestController {
	private final RuleDraftSuggestService drafts;

	public RuleDraftSuggestController(RuleDraftSuggestService drafts) {
		this.drafts = drafts;
	}

	public record Request(String cwe, String language) { }

	@PostMapping("/rule-drafts")
	public Map<String, Object> draft(@RequestBody Request body, Authentication authentication) {
		return drafts.suggest(authentication.getName(), body == null ? null : body.cwe(), body == null ? null : body.language());
	}

	@ExceptionHandler(IllegalArgumentException.class)
	public ResponseEntity<Object> invalid(IllegalArgumentException e) {
		return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
	}
}
