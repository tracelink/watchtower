package com.tracelink.appsec.watchtower.core.cwe;

import java.util.LinkedHashMap;
import java.util.Map;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * The CWE catalog chip on the Knowledge page: its state for polling, and the button that asks for an update.
 * Anyone who can see Knowledge can read the state; updating needs Rule Modify (CSRF applies to the POST).
 */
@RestController
@RequestMapping("/rules/knowledge/cwe-catalog")
public class CweCatalogController {
	private final CweCatalogService catalog;

	public CweCatalogController(CweCatalogService catalog) {
		this.catalog = catalog;
	}

	@GetMapping
	@PreAuthorize("hasAuthority('Ruleset View')")
	public CweCatalogChip state() {
		return CweCatalogChip.of(catalog.status());
	}

	/** Queues an update. {@code force} downloads again even when the stored release is current. */
	@PostMapping("/refresh")
	@PreAuthorize("hasAuthority('Rule Modify')")
	public Map<String, Object> refresh(@RequestParam(defaultValue = "false") boolean force, Authentication user) {
		boolean queued = catalog.requestRefresh(user.getName(), force);
		Map<String, Object> answer = new LinkedHashMap<>();
		answer.put("queued", queued);
		answer.put("chip", CweCatalogChip.of(catalog.status()));
		return answer;
	}
}
