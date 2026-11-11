package com.tracelink.appsec.watchtower.core.cwe;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.tracelink.appsec.watchtower.core.module.ModuleControlService;
import com.tracelink.appsec.watchtower.core.rule.LanguageScopedRule;
import com.tracelink.appsec.watchtower.core.rule.RuleDto;
import com.tracelink.appsec.watchtower.core.rule.RuleService;
import com.tracelink.appsec.watchtower.core.rule.RuleState;

/**
 * Which weaknesses in the organisation's CWE profile have a working rule, per language. Computed live from
 * the cached rules, the stored rule health and people's gap decisions; nothing is stored here.
 * <p>
 * A cell is <b>covered</b> when a rule with that CWE (primary or secondary) scans the language, its
 * module is on, its engine ran in the last 30 days and it is not flagged noisy; <b>weak</b> when rules exist
 * but none of them qualifies; otherwise a person's decision applies, else it is a <b>gap</b>. The "Other"
 * column is only shown when a rule or a decision is there, since it is not a first-wave language.
 */
@Service
public class CweCoverageService {
	static final int MAX_RULES_PER_CELL = 10;

	public static final String COVERED = "COVERED", WEAK = "WEAK", GAP = "GAP", NONE = "NONE";

	/** A language column. */
	public record Column(String key, String label) {
	}

	/** A rule that scans a cell's language for the weakness; {@code reason} says why it is not working, if so. */
	public record RuleRef(long id, String name, String module, boolean working, String reason) {
	}

	/** One weakness in one language. {@code status} is COVERED, WEAK, GAP, NONE or the decision. */
	public record Cell(String language, String status, int ruleCount, List<RuleRef> rules, String decisionNote,
			String decidedBy) {
	}

	/** One weakness of the profile with a cell per column. */
	public record Row(int cwe, String label, String name, String priority, String note, List<Cell> cells) {
	}

	/** Cell totals over the whole table. */
	public record Counts(int covered, int weak, int gap, int decided) {
	}

	public record Coverage(List<Column> columns, List<Row> rows, Counts counts, boolean catalogLoaded) {
	}

	private static final Set<String> DECISIONS = Set.of(GapDecision.NOT_APPLICABLE.name(),
			GapDecision.NOT_COVERABLE.name(), GapDecision.DEFERRED.name());
	private static final List<Column> COLUMNS = Arrays.stream(CoverageLanguage.values())
			.map(language -> new Column(language.name(), language.label())).toList();

	private final RuleService rules;
	private final CweProfileService profile;
	private final CweRuleHealthReader healthReader;
	private final CweCatalogService catalog;
	private ModuleControlService moduleControls;

	@Autowired
	public CweCoverageService(RuleService rules, CweProfileService profile, CweRuleHealthReader healthReader,
			CweCatalogService catalog) {
		this.rules = rules;
		this.profile = profile;
		this.healthReader = healthReader;
		this.catalog = catalog;
	}

	@Autowired(required = false)
	public void setModuleControls(ModuleControlService moduleControls) {
		this.moduleControls = moduleControls;
	}

	public Coverage coverage() {
		List<CweProfileService.Entry> entries = profile.list();
		if (entries.isEmpty()) {
			return new Coverage(COLUMNS, List.of(), new Counts(0, 0, 0, 0), catalog.isLoaded());
		}
		List<RuleDto> live = rules.getRules().stream()
				.filter(rule -> rule.getId() != null && rule.getStewardship().getState() != RuleState.RETIRED
						&& !rule.getStewardship().isNotSecurity())
				.toList();
		Map<Long, CweRuleHealthReader.Health> health = healthReader.read(revisions(live));
		Map<Integer, List<RuleDto>> byCwe = byCwe(live);
		Map<String, CweProfileService.Decision> decisions = new HashMap<>();
		for (CweProfileService.Decision decision : profile.decisions()) {
			decisions.put(decision.cwe() + ":" + decision.language(), decision);
		}
		Map<String, Boolean> moduleOn = new HashMap<>();
		int covered = 0, weak = 0, gap = 0, decided = 0;
		List<Row> table = new ArrayList<>();
		for (CweProfileService.Entry entry : entries) {
			List<Cell> cells = new ArrayList<>();
			for (CoverageLanguage language : CoverageLanguage.values()) {
				List<RuleRef> refs = refs(byCwe.getOrDefault(entry.cwe(), List.of()), language, health, moduleOn);
				Cell cell = cell(language, refs, decisions.get(entry.cwe() + ":" + language.name()));
				cells.add(cell);
				switch (cell.status()) {
					case COVERED -> covered++;
					case WEAK -> weak++;
					case GAP -> gap++;
					case NONE -> {
					}
					default -> decided++;
				}
			}
			table.add(new Row(entry.cwe(), entry.label(), entry.name(), entry.priority(), entry.note(), List.copyOf(cells)));
		}
		return new Coverage(COLUMNS, List.copyOf(table), new Counts(covered, weak, gap, decided), catalog.isLoaded());
	}

	private Cell cell(CoverageLanguage language, List<RuleRef> refs, CweProfileService.Decision decision) {
		List<RuleRef> shown = refs.stream().limit(MAX_RULES_PER_CELL).toList();
		if (!refs.isEmpty()) {
			boolean anyWorking = refs.stream().anyMatch(RuleRef::working);
			return new Cell(language.name(), anyWorking ? COVERED : WEAK, refs.size(), shown, null, null);
		}
		if (decision != null && DECISIONS.contains(decision.decision())) {
			return new Cell(language.name(), decision.decision(), 0, List.of(), decision.note(), decision.by());
		}
		return new Cell(language.name(), language == CoverageLanguage.OTHER ? NONE : GAP, 0, List.of(), null, null);
	}

	private List<RuleRef> refs(List<RuleDto> candidates, CoverageLanguage language,
			Map<Long, CweRuleHealthReader.Health> health, Map<String, Boolean> moduleOn) {
		List<RuleRef> refs = new ArrayList<>();
		for (RuleDto rule : candidates) {
			if (!languages(rule).contains(language)) {
				continue;
			}
			boolean on = moduleOn.computeIfAbsent(rule.getModule(), module -> moduleControls == null || moduleControls.enabled(module));
			CweRuleHealthReader.Health stored = health.get(rule.getId());
			String reason = !on ? "its scanner module is off" : stored == null || !stored.ran() ? "has not run in the last 30 days"
					: stored.noisy() ? "flagged for many false positives" : null;
			refs.add(new RuleRef(rule.getId(), rule.getName(), rule.getModule(), reason == null, reason));
		}
		refs.sort(Comparator.comparing(RuleRef::working).reversed().thenComparing(RuleRef::name, String.CASE_INSENSITIVE_ORDER));
		return refs;
	}

	/** The languages a rule scans: those its definition names, else what its scanner module covers. */
	private static Set<CoverageLanguage> languages(RuleDto rule) {
		if (rule instanceof LanguageScopedRule scoped && !scoped.scannedLanguages().isEmpty()) {
			Set<CoverageLanguage> named = EnumSet.noneOf(CoverageLanguage.class);
			scoped.scannedLanguages().forEach(language -> named.add(CoverageLanguage.of(language)));
			return named;
		}
		String module = rule.getModule() == null ? "" : rule.getModule().toLowerCase(java.util.Locale.ROOT);
		return switch (module) {
			case "pmd" -> EnumSet.of(CoverageLanguage.JAVA);
			case "eslint" -> EnumSet.of(CoverageLanguage.JAVASCRIPT);
			case "regex", "betterleaks" -> EnumSet.allOf(CoverageLanguage.class);
			default -> EnumSet.of(CoverageLanguage.OTHER);
		};
	}

	private static Map<Integer, List<RuleDto>> byCwe(List<RuleDto> live) {
		Map<Integer, List<RuleDto>> byCwe = new LinkedHashMap<>();
		for (RuleDto rule : live) {
			List<String> labels = new ArrayList<>();
			labels.add(rule.getStewardship().getCwe());
			labels.addAll(CweCatalogService.split(rule.getStewardship().getSecondaryCwes()));
			labels.stream().map(CweProfileService::number).flatMap(java.util.Optional::stream).distinct()
					.forEach(cwe -> byCwe.computeIfAbsent(cwe, key -> new ArrayList<>()).add(rule));
		}
		return byCwe;
	}

	private static Map<Long, String> revisions(List<RuleDto> live) {
		Map<Long, String> revisions = new HashMap<>();
		live.forEach(rule -> revisions.put(rule.getId(), rule.getRevision()));
		return revisions;
	}
}
