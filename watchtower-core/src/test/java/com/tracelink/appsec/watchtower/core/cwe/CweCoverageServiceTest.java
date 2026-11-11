package com.tracelink.appsec.watchtower.core.cwe;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.tracelink.appsec.watchtower.core.module.ModuleControlService;
import com.tracelink.appsec.watchtower.core.rule.CustomRuleDto;
import com.tracelink.appsec.watchtower.core.rule.LanguageScopedRule;
import com.tracelink.appsec.watchtower.core.rule.RuleEntity;
import com.tracelink.appsec.watchtower.core.rule.RuleService;
import com.tracelink.appsec.watchtower.core.rule.RuleState;

/** Which important weaknesses have a working rule, per language, from the rules, their health and people's decisions. */
class CweCoverageServiceTest {
	private final List<CustomRuleDto> rules = new ArrayList<>();
	private final List<CweProfileService.Entry> profile = new ArrayList<>();
	private final List<CweProfileService.Decision> decisions = new ArrayList<>();
	private final Map<Long, CweRuleHealthReader.Health> health = new java.util.HashMap<>();
	private CweCoverageService service;
	private ModuleControlService modules;

	/** A rule DTO with a module and, optionally, the languages its definition names. */
	private static final class CoverageRule extends CustomRuleDto implements LanguageScopedRule {
		private final String module;
		private final Set<String> languages;

		CoverageRule(String module, Set<String> languages) {
			this.module = module;
			this.languages = languages;
		}

		@Override
		public String getModule() {
			return module;
		}

		@Override
		public RuleEntity toEntity() {
			throw new UnsupportedOperationException();
		}

		@Override
		public Set<String> scannedLanguages() {
			return languages;
		}
	}

	@BeforeEach
	void setUp() {
		RuleService ruleService = mock(RuleService.class);
		when(ruleService.getRules()).thenAnswer(invocation -> List.copyOf(rules));
		CweProfileService profileService = mock(CweProfileService.class);
		when(profileService.list()).thenAnswer(invocation -> List.copyOf(profile));
		when(profileService.decisions()).thenAnswer(invocation -> List.copyOf(decisions));
		CweRuleHealthReader reader = mock(CweRuleHealthReader.class);
		when(reader.read(any())).thenAnswer(invocation -> Map.copyOf(health));
		CweCatalogService catalog = mock(CweCatalogService.class);
		when(catalog.isLoaded()).thenReturn(true);
		modules = mock(ModuleControlService.class);
		when(modules.enabled(any())).thenReturn(true);
		service = new CweCoverageService(ruleService, profileService, reader, catalog);
		service.setModuleControls(modules);
		profile.add(new CweProfileService.Entry(89, "CWE-89", "SQL Injection", "CRITICAL", null, true));
	}

	private CoverageRule rule(long id, String name, String module, Set<String> languages, String cwe, String secondary) {
		CoverageRule rule = new CoverageRule(module, languages);
		rule.setId(id);
		rule.setName(name);
		rule.getStewardship().setCwe(cwe);
		rule.getStewardship().setSecondaryCwes(secondary);
		rules.add(rule);
		return rule;
	}

	private void ran(long id, boolean ran, boolean noisy) {
		health.put(id, new CweRuleHealthReader.Health(ran, noisy));
	}

	private CweCoverageService.Cell cell(CweCoverageService.Coverage coverage, int row, String language) {
		return coverage.rows().get(row).cells().stream().filter(c -> c.language().equals(language)).findFirst().orElseThrow();
	}

	@Test
	void aRuleThatRanRecentlyAndIsNotNoisyCoversItsLanguage() {
		rule(1, "AvoidConcatenatedSql", "pmd", Set.of(), "CWE-89", null);
		ran(1, true, false);

		var coverage = service.coverage();

		assertThat(cell(coverage, 0, "JAVA").status()).isEqualTo("COVERED");
		assertThat(cell(coverage, 0, "JAVA").rules()).extracting(CweCoverageService.RuleRef::name).containsExactly("AvoidConcatenatedSql");
		assertThat(cell(coverage, 0, "PYTHON").status()).isEqualTo("GAP");
		assertThat(cell(coverage, 0, "JAVASCRIPT").status()).isEqualTo("GAP");
		assertThat(cell(coverage, 0, "OTHER").status()).as("Other only matters when a rule covers it").isEqualTo("NONE");
	}

	@Test
	void aRuleThatDidNotRunIsNoisyOrInADisabledModuleOnlyWeaklyCovers() {
		rule(1, "never-ran", "pmd", Set.of(), "CWE-89", null);
		rule(2, "noisy", "eslint", Set.of(), "CWE-89", null);
		rule(3, "module-off", "opengrep", Set.of("python"), "CWE-89", null);
		ran(1, false, false);
		ran(2, true, true);
		ran(3, true, false);
		when(modules.enabled("opengrep")).thenReturn(false);

		var coverage = service.coverage();

		assertThat(cell(coverage, 0, "JAVA").status()).isEqualTo("WEAK");
		assertThat(cell(coverage, 0, "JAVA").rules().get(0).reason()).contains("not run");
		assertThat(cell(coverage, 0, "JAVASCRIPT").status()).isEqualTo("WEAK");
		assertThat(cell(coverage, 0, "JAVASCRIPT").rules().get(0).reason()).contains("false positives");
		assertThat(cell(coverage, 0, "PYTHON").status()).isEqualTo("WEAK");
		assertThat(cell(coverage, 0, "PYTHON").rules().get(0).reason()).contains("module is off");
	}

	@Test
	void oneGoodRuleAmongWeakOnesIsEnough() {
		rule(1, "noisy", "pmd", Set.of(), "CWE-89", null);
		rule(2, "good", "pmd", Set.of(), "CWE-89", null);
		ran(1, true, true);
		ran(2, true, false);

		assertThat(cell(service.coverage(), 0, "JAVA").status()).isEqualTo("COVERED");
	}

	@Test
	void aRuleWithNoHealthEvidenceYetIsNotCountedAsWorking() {
		rule(1, "fresh", "pmd", Set.of(), "CWE-89", null);

		assertThat(cell(service.coverage(), 0, "JAVA").status()).isEqualTo("WEAK");
	}

	@Test
	void secondaryCwesCountToo() {
		rule(1, "hibernate-sql", "pmd", Set.of(), "CWE-564", "CWE-89");
		ran(1, true, false);

		assertThat(cell(service.coverage(), 0, "JAVA").status()).isEqualTo("COVERED");
	}

	@Test
	void notSecurityRulesRetiredRulesAndOtherWeaknessesDoNotCount() {
		rule(1, "style", "pmd", Set.of(), "CWE-89", null).getStewardship().setSecurityRelevance("NOT_SECURITY");
		rule(2, "retired", "pmd", Set.of(), "CWE-89", null).getStewardship().setState(RuleState.RETIRED);
		rule(3, "other-weakness", "pmd", Set.of(), "CWE-79", null);
		ran(1, true, false);
		ran(2, true, false);
		ran(3, true, false);

		assertThat(cell(service.coverage(), 0, "JAVA").status()).isEqualTo("GAP");
	}

	@Test
	void aDeprecatedRuleStillRunsSoItCounts() {
		rule(1, "phasing-out", "pmd", Set.of(), "CWE-89", null).getStewardship().setState(RuleState.DEPRECATED);
		ran(1, true, false);

		assertThat(cell(service.coverage(), 0, "JAVA").status()).isEqualTo("COVERED");
	}

	@Test
	void languagesComeFromTheRuleDefinitionOrElseTheModule() {
		rule(1, "opengrep-multi", "opengrep", Set.of("python", "TypeScript"), "CWE-89", null);
		rule(2, "secrets", "betterleaks", Set.of(), "CWE-89", null);
		rule(3, "iac", "checkov", Set.of(), "CWE-89", null);
		ran(1, true, false);
		ran(2, true, false);
		ran(3, true, false);

		var coverage = service.coverage();

		assertThat(cell(coverage, 0, "PYTHON").rules()).extracting(CweCoverageService.RuleRef::name).contains("opengrep-multi", "secrets");
		assertThat(cell(coverage, 0, "JAVASCRIPT").rules()).extracting(CweCoverageService.RuleRef::name).contains("opengrep-multi");
		assertThat(cell(coverage, 0, "JAVA").rules()).extracting(CweCoverageService.RuleRef::name).containsExactly("secrets");
		assertThat(cell(coverage, 0, "OTHER").rules()).extracting(CweCoverageService.RuleRef::name).contains("iac", "secrets");
		assertThat(cell(coverage, 0, "OTHER").status()).isEqualTo("COVERED");
	}

	@Test
	void aDecisionAnswersAGapButNeverOverridesARealRule() {
		decisions.add(new CweProfileService.Decision(89, "PYTHON", "NOT_COVERABLE", "needs taint tracking", "alice", 1L));
		decisions.add(new CweProfileService.Decision(89, "JAVASCRIPT", "DEFERRED", null, "alice", 1L));
		decisions.add(new CweProfileService.Decision(89, "JAVA", "NOT_APPLICABLE", null, "alice", 1L));
		rule(1, "sql", "pmd", Set.of(), "CWE-89", null);
		ran(1, true, false);

		var coverage = service.coverage();

		assertThat(cell(coverage, 0, "PYTHON").status()).isEqualTo("NOT_COVERABLE");
		assertThat(cell(coverage, 0, "PYTHON").decisionNote()).isEqualTo("needs taint tracking");
		assertThat(cell(coverage, 0, "JAVASCRIPT").status()).isEqualTo("DEFERRED");
		assertThat(cell(coverage, 0, "JAVA").status()).as("a working rule wins over an old decision").isEqualTo("COVERED");
	}

	@Test
	void countsSummariseTheCellsThatMatter() {
		decisions.add(new CweProfileService.Decision(89, "PYTHON", "DEFERRED", null, "alice", 1L));
		rule(1, "sql", "pmd", Set.of(), "CWE-89", null);
		ran(1, true, false);

		var counts = service.coverage().counts();

		assertThat(counts.covered()).isEqualTo(1);
		assertThat(counts.weak()).isZero();
		assertThat(counts.gap()).isEqualTo(1);
		assertThat(counts.decided()).isEqualTo(1);
	}

	@Test
	void rowsFollowTheProfileOrderAndAnEmptyProfileGivesNoRows() {
		profile.add(new CweProfileService.Entry(79, "CWE-79", "XSS", "HIGH", "web", true));

		var coverage = service.coverage();

		assertThat(coverage.rows()).extracting(CweCoverageService.Row::cwe).containsExactly(89, 79);
		assertThat(coverage.rows().get(1).note()).isEqualTo("web");
		assertThat(coverage.columns()).extracting(CweCoverageService.Column::key).containsExactly("JAVA", "PYTHON", "JAVASCRIPT", "OTHER");

		profile.clear();

		assertThat(service.coverage().rows()).isEmpty();
	}

	@Test
	void aLongRuleListIsCutButTheRealCountIsKept() {
		for (int i = 0; i < 15; i++) {
			rule(100 + i, "rule-" + i, "pmd", Set.of(), "CWE-89", null);
			ran(100 + i, true, false);
		}

		var java = cell(service.coverage(), 0, "JAVA");

		assertThat(java.ruleCount()).isEqualTo(15);
		assertThat(java.rules()).hasSize(CweCoverageService.MAX_RULES_PER_CELL);
	}
}
