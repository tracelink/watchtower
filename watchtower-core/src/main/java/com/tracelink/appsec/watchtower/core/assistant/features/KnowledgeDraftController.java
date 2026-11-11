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

/**
 * Asks the assistant to draft the fields of a Knowledge proposal from the evidence a person chose. It returns
 * text for the form; it proposes and stores nothing.
 */
@RestController
@RequestMapping("/assistant")
@PreAuthorize("hasAuthority('Assistant Use')")
public class KnowledgeDraftController {
	private final KnowledgeDraftService drafts;

	public KnowledgeDraftController(KnowledgeDraftService drafts) {
		this.drafts = drafts;
	}

	public record Request(List<KnowledgeDraftService.Ref> evidence) { }

	@PostMapping("/knowledge-draft")
	public Map<String, Object> draft(@RequestBody Request body, Authentication authentication) {
		return drafts.draft(authentication.getName(), body == null ? null : body.evidence());
	}

	@ExceptionHandler(IllegalArgumentException.class)
	public ResponseEntity<Object> invalid(IllegalArgumentException e) {
		return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
	}
}
