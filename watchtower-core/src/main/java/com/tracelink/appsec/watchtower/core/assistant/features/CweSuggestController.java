package com.tracelink.appsec.watchtower.core.assistant.features;

import java.util.List;
import java.util.Map;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** Asks for CWE suggestions for the rules a person selected on Rule work. It returns a draft and saves nothing. */
@RestController
@RequestMapping("/assistant")
@PreAuthorize("hasAuthority('Assistant Use')")
public class CweSuggestController {
	private final CweSuggestService suggestions;

	public CweSuggestController(CweSuggestService suggestions) {
		this.suggestions = suggestions;
	}

	public record Request(List<Long> ruleIds) { }

	@PostMapping("/cwe-suggestions")
	public Map<String, Object> suggest(@RequestBody Request body, Authentication authentication) {
		return suggestions.suggest(authentication.getName(), body == null ? null : body.ruleIds());
	}

	@ExceptionHandler(IllegalArgumentException.class)
	public ResponseEntity<Object> invalid(IllegalArgumentException e) {
		return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
	}
}
