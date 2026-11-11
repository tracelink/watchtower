package com.tracelink.appsec.watchtower.core.assistant.review;

import java.util.List;
import java.util.Map;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * The AI review of picked files: which files can be chosen, starting a review, reading it, and a person's decision
 * about each point. It gathers advice; nothing here changes a rule or judges a finding.
 */
@RestController
@RequestMapping("/assistant/ai-review")
@PreAuthorize("hasAuthority('Assistant Use')")
public class AiReviewController {
	private final AiReviewService review;

	public AiReviewController(AiReviewService review) {
		this.review = review;
	}

	/** {@code focus} is an optional plain-words note about what to look at; it is checked before it is used. */
	public record Start(String scanType, Long scanId, List<String> paths, String focus) { }

	@GetMapping("/files/{scanType}/{scanId}")
	public Map<String, Object> files(@PathVariable String scanType, @PathVariable long scanId, Authentication user) {
		return review.candidates(user.getName(), scanType, scanId);
	}

	@PostMapping
	public ResponseEntity<Map<String, Object>> start(@RequestBody Start request, Authentication user) {
		if (request == null || request.scanId() == null) {
			throw new IllegalArgumentException("scanType and scanId are required");
		}
		return ResponseEntity.accepted().body(review.start(user.getName(), request.scanType(), request.scanId(), request.paths(), request.focus()));
	}

	@GetMapping("/scan/{scanType}/{scanId}")
	public Map<String, Object> latest(@PathVariable String scanType, @PathVariable long scanId, Authentication user) {
		return review.latest(user.getName(), scanType, scanId);
	}

	@GetMapping("/runs/{runId}")
	public Map<String, Object> view(@PathVariable String runId, Authentication user) {
		return review.view(user.getName(), runId);
	}

	@PostMapping("/runs/{runId}/resume")
	public ResponseEntity<Map<String, Object>> resume(@PathVariable String runId, Authentication user) {
		return ResponseEntity.accepted().body(review.resume(user.getName(), runId));
	}

	@PostMapping("/items/{itemId}/{action}")
	public Map<String, Object> act(@PathVariable String itemId, @PathVariable String action, Authentication user) {
		return review.act(user.getName(), itemId, action);
	}

	@ExceptionHandler(IllegalArgumentException.class)
	public ResponseEntity<Object> invalid(IllegalArgumentException e) {
		return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
	}
}
