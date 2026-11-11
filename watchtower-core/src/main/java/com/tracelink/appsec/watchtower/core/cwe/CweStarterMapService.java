package com.tracelink.appsec.watchtower.core.cwe;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Pattern;

import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.tracelink.appsec.watchtower.core.exception.rule.RuleNotFoundException;
import com.tracelink.appsec.watchtower.core.rule.RuleDto;
import com.tracelink.appsec.watchtower.core.rule.RuleException;
import com.tracelink.appsec.watchtower.core.rule.RuleService;
import com.tracelink.appsec.watchtower.core.rule.RuleState;

/**
 * Fills in a first CWE for rules that have none, from a small curated map (no scanner ships CWE tags).
 * The map is a bundled resource keyed by scanner module and rule name, plus module-wide entries. It only
 * ever touches rules without a CWE that are not marked "not a security rule", only uses CWEs that exist in
 * the loaded catalog and may be used for a new mapping, and is applied after a preview.
 */
@Service
public class CweStarterMapService {
	private static final String RESOURCE = "cwe/starter-rule-cwe-map.json";
	private static final Pattern CWE = Pattern.compile("CWE-[1-9][0-9]{0,8}");
	private static final int CHUNK = RuleService.MAX_BULK_STEWARDSHIP;

	/** A rule that would get a CWE. */
	public record Proposal(long ruleId, String name, String module, String cwe, String cweName) {
	}

	/** What applying would do; {@code skippedUnknownCwe} counts rules whose mapped CWE the catalog no longer allows. */
	public record Preview(List<Proposal> proposals, int skippedUnknownCwe) {
	}

	private final RuleService rules;
	private final CweCatalogService catalog;
	private final Map<String, String> moduleCwes;
	private final Map<String, String> ruleCwes;

	public CweStarterMapService(RuleService rules, CweCatalogService catalog) {
		this.rules = rules;
		this.catalog = catalog;
		Map<String, String> modules = new LinkedHashMap<>();
		Map<String, String> byRule = new LinkedHashMap<>();
		load(modules, byRule);
		this.moduleCwes = Map.copyOf(modules);
		this.ruleCwes = Map.copyOf(byRule);
	}

	int mappedRuleCount() {
		return ruleCwes.size();
	}

	Map<String, String> moduleCwes() {
		return moduleCwes;
	}

	public Preview preview() {
		requireCatalog();
		List<Proposal> proposals = new ArrayList<>();
		int skipped = 0;
		for (RuleDto rule : rules.getRules()) {
			Optional<String> mapped = mappedCwe(rule);
			if (mapped.isEmpty()) {
				continue;
			}
			Optional<CweEntry> entry = catalog.find(mapped.get()).filter(CweEntry::isMappable);
			if (entry.isEmpty()) {
				skipped++;
				continue;
			}
			proposals.add(new Proposal(rule.getId(), rule.getName(), rule.getModule(), mapped.get(), entry.get().name()));
		}
		return new Preview(List.copyOf(proposals), skipped);
	}

	/** Applies the previewed CWEs, a hundred rules at a time, and returns how many rules were changed. */
	public int apply(String actor) {
		List<Proposal> proposals = preview().proposals();
		int changed = 0;
		try {
			for (int from = 0; from < proposals.size(); from += CHUNK) {
				Map<Long, String> chunk = new LinkedHashMap<>();
				proposals.subList(from, Math.min(proposals.size(), from + CHUNK))
						.forEach(proposal -> chunk.put(proposal.ruleId(), proposal.cwe()));
				changed += rules.applyCwes(chunk, actor);
			}
		} catch (RuleException | RuleNotFoundException e) {
			throw new IllegalArgumentException(changed + " rules were updated before this stopped: " + e.getMessage(), e);
		}
		return changed;
	}

	private void requireCatalog() {
		if (!catalog.isLoaded()) {
			throw new IllegalArgumentException("Load the CWE catalog on the Knowledge page first.");
		}
	}

	/** Only rules that are live, are security rules and have no CWE are considered. */
	private Optional<String> mappedCwe(RuleDto rule) {
		var stewardship = rule.getStewardship();
		boolean hasCwe = stewardship.getCwe() != null && !stewardship.getCwe().isBlank();
		if (rule.getId() == null || hasCwe || stewardship.isNotSecurity() || stewardship.getState() == RuleState.RETIRED
				|| rule.getModule() == null || rule.getName() == null) {
			return Optional.empty();
		}
		String module = rule.getModule().toLowerCase(Locale.ROOT);
		String byRule = ruleCwes.get(key(module, rule.getName()));
		return Optional.ofNullable(byRule != null ? byRule : moduleCwes.get(module));
	}

	private static String key(String module, String name) {
		return module.toLowerCase(Locale.ROOT) + "/" + name;
	}

	private static void load(Map<String, String> modules, Map<String, String> byRule) {
		try (InputStream in = new ClassPathResource(RESOURCE).getInputStream()) {
			JsonNode map = new ObjectMapper().readTree(in);
			map.path("modules").fields().forEachRemaining(entry -> modules.put(entry.getKey().toLowerCase(Locale.ROOT), checked(entry.getValue().asText())));
			for (JsonNode rule : map.path("rules")) {
				byRule.put(key(rule.path("module").asText(), rule.path("name").asText()), checked(rule.path("cwe").asText()));
			}
		} catch (IOException e) {
			throw new UncheckedIOException("The bundled starter CWE map cannot be read", e);
		}
	}

	private static String checked(String cwe) {
		if (!CWE.matcher(cwe).matches()) {
			throw new IllegalStateException("The bundled starter CWE map has an invalid CWE: " + cwe);
		}
		return cwe;
	}
}
