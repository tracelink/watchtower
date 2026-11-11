package com.tracelink.appsec.watchtower.core.ruleset;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.BDDMockito;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import com.tracelink.appsec.watchtower.core.mock.MockRuleEntity;
import com.tracelink.appsec.watchtower.core.rule.RuleDto;
import com.tracelink.appsec.watchtower.core.rule.RulePriority;
import com.tracelink.appsec.watchtower.core.rule.RuleRepository;
import com.tracelink.appsec.watchtower.core.rule.RuleService;
import com.tracelink.appsec.watchtower.core.scan.repository.RepositoryRepository;

@ExtendWith(SpringExtension.class)
public class RuleImpexTest {
	@MockitoBean
	private RulesetRepository mockRulesetRepository;
	@MockitoBean
	private RuleRepository mockRuleRepository;
	@MockitoBean
	private RepositoryRepository mockRepositoryRepository;

	private MockHttpServletResponse mockResponse;
	private RulesetService rulesetService;
	private RuleService ruleService;

	@BeforeEach
	public void setup() {
		this.ruleService = new RuleService(mockRuleRepository);
		this.rulesetService =
				new RulesetService(mockRulesetRepository, ruleService, mockRepositoryRepository);
		this.mockResponse = new MockHttpServletResponse();
	}

	private MockRuleEntity makeNewRule(String ruleName, String author, String message, String ext,
			RulePriority priority, boolean isProvided) {
		MockRuleEntity rule = new MockRuleEntity(isProvided);
		rule.setName(ruleName);
		rule.setAuthor(author);
		rule.setPriority(priority);
		rule.setMessage(message);
		rule.setExternalUrl(ext);
		return rule;
	}

	private RulesetEntity makeNewRuleset(String rulesetName, String description,
			RulesetDesignation designation) {
		RulesetEntity ruleset = new RulesetEntity();
		ruleset.setName(rulesetName);
		ruleset.setDescription(description);
		ruleset.setDesignation(designation);
		return ruleset;
	}

	@Test
	public void testNewRulesetNewRulesExportImport() throws Exception {
		String username = "username";

		// importing rule has no author, will be updated by the import username option
		MockRuleEntity rule =
				makeNewRule("ruleName", "", "msg", "http://example.com", RulePriority.MEDIUM,
						false);
		RulesetEntity ruleset =
				makeNewRuleset("rulesetName", "Desc", RulesetDesignation.SUPPORTING);
		ruleset.setRules(Collections.singleton(rule));

		BDDMockito.when(mockRulesetRepository.findById(BDDMockito.anyLong()))
				.thenReturn(Optional.of(ruleset));
		BDDMockito.when(mockRulesetRepository.saveAndFlush(BDDMockito.any()))
				.then(e -> e.getArgument(0));
		BDDMockito.when(mockRuleRepository.saveAll(BDDMockito.anyCollection()))
				.then(e -> new ArrayList<>(e.getArgument(0)));
		rulesetService.exportRuleset(1, mockResponse);
		byte[] content = mockResponse.getContentAsByteArray();
		RulesetDto dto;
		try (InputStream is = new ByteArrayInputStream(content)) {
			dto = rulesetService.importRuleset(is, username);
		}
		Assertions.assertEquals(ruleset.getName(), dto.getName());
		Assertions.assertEquals(ruleset.getDescription(), dto.getDescription());
		Assertions.assertEquals(ruleset.getDesignation(), dto.getDesignation());
		Assertions.assertEquals(1, dto.getRules().size());
		RuleDto importedRule = dto.getRules().iterator().next();
		Assertions.assertEquals(username, importedRule.getAuthor());
		Assertions.assertEquals(rule.getExternalUrl(), importedRule.getExternalUrl());
		Assertions.assertEquals(rule.getMessage(), importedRule.getMessage());
		Assertions.assertEquals(rule.toDto().getModule(), importedRule.getModule());
		Assertions.assertEquals(rule.getName(), importedRule.getName());
		Assertions.assertEquals(rule.getPriority(), importedRule.getPriority());
		Assertions.assertEquals(rule.toDto().getRuleDesignation(),
				importedRule.getRuleDesignation());
	}

	@Test
	public void testNewRulesetExistingRulesExportImport() throws Exception {
		String username = "username";

		MockRuleEntity rule =
				makeNewRule("ruleName", username, "msg", "http://example.com", RulePriority.MEDIUM,
						false);
		MockRuleEntity existingRule =
				makeNewRule("ruleName", username, "existingmsg",
						"http://existing.example.com", RulePriority.LOW,
						false);
		RulesetEntity ruleset =
				makeNewRuleset("rulesetName", "Desc", RulesetDesignation.SUPPORTING);
		ruleset.setRules(Collections.singleton(rule));

		BDDMockito.when(mockRulesetRepository.findById(BDDMockito.anyLong()))
				.thenReturn(Optional.of(ruleset));
		BDDMockito.when(mockRulesetRepository.saveAndFlush(BDDMockito.any()))
				.then(e -> e.getArgument(0));
		BDDMockito.when(mockRuleRepository.findByName(existingRule.getName()))
				.thenReturn(existingRule);
		BDDMockito.when(mockRuleRepository.saveAll(BDDMockito.anyCollection()))
				.then(e -> new ArrayList<>(e.getArgument(0)));
		rulesetService.exportRuleset(1, mockResponse);
		byte[] content = mockResponse.getContentAsByteArray();
		RulesetDto dto;
		try (InputStream is = new ByteArrayInputStream(content)) {
			dto = rulesetService.importRuleset(is, username);
		}
		Assertions.assertEquals(ruleset.getName(), dto.getName());
		Assertions.assertEquals(ruleset.getDescription(), dto.getDescription());
		Assertions.assertEquals(ruleset.getDesignation(), dto.getDesignation());
		Assertions.assertEquals(1, dto.getRules().size());
		RuleDto importedRule = dto.getRules().iterator().next();
		// Note that these don't check the existing rule, just the newly imported one
		Assertions.assertEquals(rule.getAuthor(), importedRule.getAuthor());
		Assertions.assertEquals(rule.getExternalUrl(), importedRule.getExternalUrl());
		Assertions.assertEquals(rule.getMessage(), importedRule.getMessage());
		Assertions.assertEquals(rule.toDto().getModule(), importedRule.getModule());
		Assertions.assertEquals(rule.getName(), importedRule.getName());
		Assertions.assertEquals(rule.getPriority(), importedRule.getPriority());
		Assertions.assertEquals(rule.toDto().getRuleDesignation(),
				importedRule.getRuleDesignation());
	}

	@Test
	public void testNewRulesetExistingRulesProvidedExportImport() throws Exception {
		String username = "username";

		MockRuleEntity rule =
				makeNewRule("ruleName", username, "msg", "http://example.com", RulePriority.HIGH,
						true);
		MockRuleEntity existingRule =
				makeNewRule("ruleName", username, "existingmsg",
						"http://existing.example.com", RulePriority.MEDIUM,
						true);
		RulesetEntity ruleset =
				makeNewRuleset("rulesetName", "Desc", RulesetDesignation.SUPPORTING);
		ruleset.setRules(Collections.singleton(rule));

		BDDMockito.when(mockRulesetRepository.findById(BDDMockito.anyLong()))
				.thenReturn(Optional.of(ruleset));
		BDDMockito.when(mockRulesetRepository.saveAndFlush(BDDMockito.any()))
				.then(e -> e.getArgument(0));
		BDDMockito.when(mockRuleRepository.findByName(existingRule.getName()))
				.thenReturn(existingRule);
		BDDMockito.when(mockRuleRepository.saveAll(BDDMockito.anyCollection()))
				.then(e -> new ArrayList<>(e.getArgument(0)));
		rulesetService.exportRuleset(1, mockResponse);
		byte[] content = mockResponse.getContentAsByteArray();
		RulesetDto dto;
		try (InputStream is = new ByteArrayInputStream(content)) {
			dto = rulesetService.importRuleset(is, username);
		}
		Assertions.assertEquals(ruleset.getName(), dto.getName());
		Assertions.assertEquals(ruleset.getDescription(), dto.getDescription());
		Assertions.assertEquals(ruleset.getDesignation(), dto.getDesignation());
		Assertions.assertEquals(1, dto.getRules().size());
		RuleDto importedRule = dto.getRules().iterator().next();
		Assertions.assertEquals("system", importedRule.getAuthor());
		Assertions.assertEquals(existingRule.getExternalUrl(), importedRule.getExternalUrl());
		Assertions.assertEquals(existingRule.getMessage(), importedRule.getMessage());
		Assertions.assertEquals(existingRule.toDto().getModule(), importedRule.getModule());
		Assertions.assertEquals(existingRule.getName(), importedRule.getName());
		// Check the new rule priority updated over the existing one
		Assertions.assertEquals(rule.getPriority(), importedRule.getPriority());
		Assertions.assertEquals(existingRule.toDto().getRuleDesignation(),
				importedRule.getRuleDesignation());
	}

	@Test
	public void testExistingRulesetNewRulesExportImport() throws Exception {
		String username = "username";

		// importing rule has no author, will be updated by the import username option
		MockRuleEntity rule =
				makeNewRule("ruleName", "", "msg", "http://example.com", RulePriority.MEDIUM,
						false);
		RulesetEntity ruleset =
				makeNewRuleset("rulesetName", "Desc", RulesetDesignation.SUPPORTING);
		RulesetEntity existingRuleset =
				makeNewRuleset("rulesetName", "existingDesc",
						RulesetDesignation.SUPPORTING);
		ruleset.setRules(Collections.singleton(rule));
		BDDMockito.when(mockRulesetRepository.findByName(existingRuleset.getName()))
				.thenReturn(existingRuleset);
		BDDMockito.when(mockRulesetRepository.findById(BDDMockito.anyLong()))
				.thenReturn(Optional.of(ruleset));
		BDDMockito.when(mockRulesetRepository.saveAndFlush(BDDMockito.any()))
				.then(e -> e.getArgument(0));
		BDDMockito.when(mockRuleRepository.saveAll(BDDMockito.anyCollection()))
				.then(e -> new ArrayList<>(e.getArgument(0)));
		rulesetService.exportRuleset(1, mockResponse);
		byte[] content = mockResponse.getContentAsByteArray();
		RulesetDto dto;
		try (InputStream is = new ByteArrayInputStream(content)) {
			dto = rulesetService.importRuleset(is, username);
		}
		Assertions.assertEquals(ruleset.getName(), dto.getName());
		Assertions.assertEquals(ruleset.getDescription(), dto.getDescription());
		Assertions.assertEquals(ruleset.getDesignation(), dto.getDesignation());
		Assertions.assertEquals(1, dto.getRules().size());
		RuleDto importedRule = dto.getRules().iterator().next();
		Assertions.assertEquals(username, importedRule.getAuthor());
		Assertions.assertEquals(rule.getExternalUrl(), importedRule.getExternalUrl());
		Assertions.assertEquals(rule.getMessage(), importedRule.getMessage());
		Assertions.assertEquals(rule.toDto().getModule(), importedRule.getModule());
		Assertions.assertEquals(rule.getName(), importedRule.getName());
		Assertions.assertEquals(rule.getPriority(), importedRule.getPriority());
		Assertions.assertEquals(rule.toDto().getRuleDesignation(),
				importedRule.getRuleDesignation());
	}

	@Test
	public void testExistingRulesetProvidedNewRulesExportImport() throws Exception {
		String username = "username";

		// importing rule has no author, will be updated by the import username option
		MockRuleEntity rule =
				makeNewRule("ruleName", "", "msg", "http://example.com", RulePriority.MEDIUM,
						false);
		RulesetEntity ruleset =
				makeNewRuleset("rulesetName", "Desc", RulesetDesignation.SUPPORTING);
		RulesetEntity existingRuleset =
				makeNewRuleset("rulesetName", "existingDesc",
						RulesetDesignation.PROVIDED);
		ruleset.setRules(Collections.singleton(rule));
		BDDMockito.when(mockRulesetRepository.findByName(existingRuleset.getName()))
				.thenReturn(existingRuleset);
		BDDMockito.when(mockRulesetRepository.findById(BDDMockito.anyLong()))
				.thenReturn(Optional.of(ruleset));
		BDDMockito.when(mockRulesetRepository.saveAndFlush(BDDMockito.any()))
				.then(e -> e.getArgument(0));
		BDDMockito.when(mockRuleRepository.saveAll(BDDMockito.anyCollection()))
				.then(e -> new ArrayList<>(e.getArgument(0)));
		rulesetService.exportRuleset(1, mockResponse);
		byte[] content = mockResponse.getContentAsByteArray();
		RulesetDto dto;
		try (InputStream is = new ByteArrayInputStream(content)) {
			dto = rulesetService.importRuleset(is, username);
		}
		Assertions.assertEquals(ruleset.getName(), dto.getName());
		Assertions.assertEquals(ruleset.getDescription(), dto.getDescription());
		// designation is not updated
		Assertions.assertEquals(existingRuleset.getDesignation(), dto.getDesignation());
		Assertions.assertEquals(1, dto.getRules().size());
		RuleDto importedRule = dto.getRules().iterator().next();
		Assertions.assertEquals(username, importedRule.getAuthor());
		Assertions.assertEquals(rule.getExternalUrl(), importedRule.getExternalUrl());
		Assertions.assertEquals(rule.getMessage(), importedRule.getMessage());
		Assertions.assertEquals(rule.toDto().getModule(), importedRule.getModule());
		Assertions.assertEquals(rule.getName(), importedRule.getName());
		Assertions.assertEquals(rule.getPriority(), importedRule.getPriority());
		Assertions.assertEquals(rule.toDto().getRuleDesignation(),
				importedRule.getRuleDesignation());
	}

	@Test
	public void testNewRulesetNewRulesExportImportInherited() throws Exception {
		String username = "username";

		// importing rule has no author, will be updated by the import username option
		MockRuleEntity rule =
				makeNewRule("ruleName", "", "msg", "http://example.com", RulePriority.MEDIUM,
						false);
		RulesetEntity ruleset =
				makeNewRuleset("rulesetName", "Desc", RulesetDesignation.SUPPORTING);
		RulesetEntity rulesetInherit =
				makeNewRuleset("rulesetNameInherit", "DescInherit", RulesetDesignation.SUPPORTING);

		ruleset.setRules(Collections.singleton(rule));
		ruleset.setRulesets(Collections.singleton(rulesetInherit));
		BDDMockito.when(mockRulesetRepository.findById(BDDMockito.anyLong()))
				.thenReturn(Optional.of(ruleset));
		BDDMockito.when(mockRulesetRepository.saveAndFlush(BDDMockito.any()))
				.then(e -> e.getArgument(0));
		BDDMockito.when(mockRuleRepository.saveAll(BDDMockito.anyCollection()))
				.then(e -> new ArrayList<>(e.getArgument(0)));
		rulesetService.exportRuleset(1, mockResponse);
		byte[] content = mockResponse.getContentAsByteArray();
		RulesetDto dto;
		try (InputStream is = new ByteArrayInputStream(content)) {
			dto = rulesetService.importRuleset(is, username);
		}
		Assertions.assertEquals(ruleset.getName(), dto.getName());
		Assertions.assertEquals(ruleset.getDescription(), dto.getDescription());
		Assertions.assertEquals(ruleset.getDesignation(), dto.getDesignation());

		Assertions.assertEquals(1, dto.getRules().size());
		RuleDto importedRule = dto.getRules().iterator().next();
		Assertions.assertEquals(username, importedRule.getAuthor());
		Assertions.assertEquals(rule.getExternalUrl(), importedRule.getExternalUrl());
		Assertions.assertEquals(rule.getMessage(), importedRule.getMessage());
		Assertions.assertEquals(rule.toDto().getModule(), importedRule.getModule());
		Assertions.assertEquals(rule.getName(), importedRule.getName());
		Assertions.assertEquals(rule.getPriority(), importedRule.getPriority());
		Assertions.assertEquals(rule.toDto().getRuleDesignation(),
				importedRule.getRuleDesignation());

		Assertions.assertEquals(1, dto.getRulesets().size());
		RulesetDto importedRuleset = dto.getRulesets().iterator().next();
		Assertions.assertEquals(rulesetInherit.getName(), importedRuleset.getName());
		Assertions.assertEquals(rulesetInherit.getDescription(), importedRuleset.getDescription());
		Assertions.assertEquals(rulesetInherit.getDesignation(), importedRuleset.getDesignation());
	}

	///////////////////////////////////////
	// Register Provided Tests
	///////////////////////////////////////

	@Test
	public void testRegisterProvidedRulesets() throws Exception {
		String moduleName = "module";
		// importing rule has no author, will be updated by the import username option
		MockRuleEntity rule =
				makeNewRule("ruleName", "", "msg", "http://example.com", RulePriority.MEDIUM,
						true);
		RulesetEntity ruleset =
				makeNewRuleset("rulesetName", "Desc", RulesetDesignation.PROVIDED);

		ruleset.setRules(Collections.singleton(rule));
		BDDMockito.when(mockRulesetRepository.findById(BDDMockito.anyLong()))
				.thenReturn(Optional.of(ruleset));
		BDDMockito.when(mockRulesetRepository.saveAndFlush(BDDMockito.any()))
				.then(e -> e.getArgument(0));
		BDDMockito.when(mockRuleRepository.saveAll(BDDMockito.anyCollection()))
				.then(e -> new ArrayList<>(e.getArgument(0)));

		List<RulesetDto> dtos =
				rulesetService.registerProvidedRulesets(moduleName, Arrays.asList(ruleset.toDto()));

		Assertions.assertEquals(1, dtos.size());
		RulesetDto dto = dtos.get(0);

		Assertions.assertTrue(dto.getName().contains(ruleset.getName()));
		Assertions.assertTrue(dto.getName().contains(moduleName));
		Assertions.assertEquals(ruleset.getDescription(), dto.getDescription());
		Assertions.assertEquals(ruleset.getDesignation(), dto.getDesignation());

		Assertions.assertEquals(1, dto.getRules().size());
		RuleDto importedRule = dto.getRules().iterator().next();
		Assertions.assertEquals("system", importedRule.getAuthor());
		Assertions.assertEquals(rule.getExternalUrl(), importedRule.getExternalUrl());
		Assertions.assertEquals(rule.getMessage(), importedRule.getMessage());
		Assertions.assertEquals(rule.toDto().getModule(), importedRule.getModule());
		Assertions.assertEquals(rule.getName(), importedRule.getName());
		Assertions.assertEquals(rule.getPriority(), importedRule.getPriority());
		Assertions.assertEquals(rule.toDto().getRuleDesignation(),
				importedRule.getRuleDesignation());
	}

	/** A provided ruleset of one rule, with the repository mocks a first import needs. */
	private RulesetEntity givenProvidedRuleset(String message) {
		MockRuleEntity rule = makeNewRule("ruleName", "", message, "http://example.com",
				RulePriority.MEDIUM, true);
		RulesetEntity ruleset = makeNewRuleset("rulesetName", "Desc", RulesetDesignation.PROVIDED);
		ruleset.setRules(Collections.singleton(rule));
		BDDMockito.when(mockRulesetRepository.saveAndFlush(BDDMockito.any()))
				.then(e -> e.getArgument(0));
		BDDMockito.when(mockRuleRepository.saveAll(BDDMockito.anyCollection()))
				.then(e -> new ArrayList<>(e.getArgument(0)));
		return ruleset;
	}

	/** Registers once and returns the fingerprint state it saved. */
	private ProvidedRulesStateEntity firstImport(ProvidedRulesStateRepository stateRepository,
			RulesetEntity ruleset) throws Exception {
		rulesetService.registerProvidedRulesets("module", List.of(ruleset.toDto()));
		ArgumentCaptor<ProvidedRulesStateEntity> saved =
				ArgumentCaptor.forClass(ProvidedRulesStateEntity.class);
		BDDMockito.verify(stateRepository).save(saved.capture());
		return saved.getValue();
	}

	@Test
	public void testRegisterProvidedRulesetsRecordsTheModulesFingerprint() throws Exception {
		ProvidedRulesStateRepository stateRepository =
				BDDMockito.mock(ProvidedRulesStateRepository.class);
		rulesetService.setProvidedRulesStateRepository(stateRepository);

		ProvidedRulesStateEntity state = firstImport(stateRepository, givenProvidedRuleset("msg"));

		Assertions.assertEquals("module", state.getModuleName());
		Assertions.assertEquals(64, state.getFingerprint().length());
	}

	@Test
	public void testUnchangedProvidedRulesetsAreNotImportedAgain() throws Exception {
		ProvidedRulesStateRepository stateRepository =
				BDDMockito.mock(ProvidedRulesStateRepository.class);
		rulesetService.setProvidedRulesStateRepository(stateRepository);
		RulesetEntity ruleset = givenProvidedRuleset("msg");
		ProvidedRulesStateEntity state = firstImport(stateRepository, ruleset);
		BDDMockito.when(stateRepository.findById("module")).thenReturn(Optional.of(state));
		RulesetEntity stored = makeNewRuleset("module - rulesetName", "Desc",
				RulesetDesignation.PROVIDED);
		BDDMockito.when(mockRulesetRepository.findByName("module - rulesetName"))
				.thenReturn(stored);
		BDDMockito.clearInvocations(mockRuleRepository, mockRulesetRepository, stateRepository);

		// A fresh DTO, as the next boot builds it
		List<RulesetDto> imported =
				rulesetService.registerProvidedRulesets("module", List.of(ruleset.toDto()));

		Assertions.assertTrue(imported.isEmpty());
		BDDMockito.verify(mockRuleRepository, BDDMockito.never())
				.saveAll(BDDMockito.anyCollection());
		BDDMockito.verify(mockRulesetRepository, BDDMockito.never()).saveAndFlush(BDDMockito.any());
		BDDMockito.verify(mockRulesetRepository, BDDMockito.never()).findAll();
		BDDMockito.verify(stateRepository, BDDMockito.never()).save(BDDMockito.any());
	}

	@Test
	public void testChangedProvidedRulesetsAreImported() throws Exception {
		ProvidedRulesStateRepository stateRepository =
				BDDMockito.mock(ProvidedRulesStateRepository.class);
		rulesetService.setProvidedRulesStateRepository(stateRepository);
		ProvidedRulesStateEntity state = firstImport(stateRepository, givenProvidedRuleset("msg"));
		BDDMockito.when(stateRepository.findById("module")).thenReturn(Optional.of(state));
		BDDMockito.when(mockRulesetRepository.findByName("module - rulesetName"))
				.thenReturn(makeNewRuleset("module - rulesetName", "Desc",
						RulesetDesignation.PROVIDED));
		BDDMockito.clearInvocations(mockRuleRepository, stateRepository);

		rulesetService.registerProvidedRulesets("module",
				List.of(givenProvidedRuleset("a new message").toDto()));

		BDDMockito.verify(mockRuleRepository).saveAll(BDDMockito.anyCollection());
		BDDMockito.verify(stateRepository).save(BDDMockito.any());
	}

	@Test
	public void testAMissingProvidedRulesetIsImportedEvenIfTheFingerprintMatches()
			throws Exception {
		ProvidedRulesStateRepository stateRepository =
				BDDMockito.mock(ProvidedRulesStateRepository.class);
		rulesetService.setProvidedRulesStateRepository(stateRepository);
		RulesetEntity ruleset = givenProvidedRuleset("msg");
		ProvidedRulesStateEntity state = firstImport(stateRepository, ruleset);
		BDDMockito.when(stateRepository.findById("module")).thenReturn(Optional.of(state));
		// findByName answers null: someone deleted the ruleset since the last import.
		BDDMockito.clearInvocations(mockRuleRepository);

		rulesetService.registerProvidedRulesets("module", List.of(ruleset.toDto()));

		BDDMockito.verify(mockRuleRepository).saveAll(BDDMockito.anyCollection());
	}

	@Test
	public void testRegisterProvidedRulesetsRemoveDeprecatedRulesetsAndRules() throws Exception {
		ruleService.setStewardshipHistoryRepository(BDDMockito.mock(
				com.tracelink.appsec.watchtower.core.rule.RuleStewardshipHistoryRepository.class));
		String moduleName = "module";
		// importing rule has no author, will be updated by the import username option
		MockRuleEntity rule =
				makeNewRule("ruleName", "", "msg", "http://example.com", RulePriority.MEDIUM,
						true);
		RulesetEntity ruleset =
				makeNewRuleset("rulesetName", "Desc", RulesetDesignation.PROVIDED);
		ruleset.setRules(Collections.singleton(rule));

		MockRuleEntity deprecatedRule = makeNewRule("deprecatedRule", "deprecatedAuthor",
				"deprecatedMsg", "http://deprecated.com", RulePriority.HIGH, true);
		deprecatedRule.setId(123L);
		RulesetEntity deprecatedRuleset =
				makeNewRuleset(moduleName + "-deprecatedRulesetName", "deprecatedDesc",
						RulesetDesignation.PROVIDED);
		deprecatedRuleset.setRules(new HashSet<>(Arrays.asList(deprecatedRule)));

		BDDMockito.when(mockRuleRepository.findById(deprecatedRule.getId()))
				.thenReturn(Optional.of(deprecatedRule));
		BDDMockito.when(mockRuleRepository.findAll())
				.thenReturn(Arrays.asList(deprecatedRule));
		BDDMockito.when(mockRulesetRepository.findByName(deprecatedRuleset.getName()))
				.thenReturn(deprecatedRuleset);

		BDDMockito.when(mockRulesetRepository.findAll())
				.thenReturn(Arrays.asList(deprecatedRuleset));
		BDDMockito.when(mockRulesetRepository.findById(BDDMockito.anyLong()))
				.thenReturn(Optional.of(ruleset));
		BDDMockito.when(mockRulesetRepository.saveAndFlush(BDDMockito.any()))
				.then(e -> e.getArgument(0));
		BDDMockito.when(mockRuleRepository.saveAll(BDDMockito.anyCollection()))
				.then(e -> new ArrayList<>(e.getArgument(0)));

		List<RulesetDto> dtos =
				rulesetService.registerProvidedRulesets(moduleName, Arrays.asList(ruleset.toDto()));

		Assertions.assertEquals(1, dtos.size());
		RulesetDto dto = dtos.get(0);

		Assertions.assertTrue(dto.getName().contains(ruleset.getName()));
		Assertions.assertTrue(dto.getName().contains(moduleName));
		Assertions.assertEquals(ruleset.getDescription(), dto.getDescription());
		Assertions.assertEquals(ruleset.getDesignation(), dto.getDesignation());

		Assertions.assertEquals(1, dto.getRules().size());
		RuleDto importedRule = dto.getRules().iterator().next();
		Assertions.assertEquals("system", importedRule.getAuthor());
		Assertions.assertEquals(rule.getExternalUrl(), importedRule.getExternalUrl());
		Assertions.assertEquals(rule.getMessage(), importedRule.getMessage());
		Assertions.assertEquals(rule.toDto().getModule(), importedRule.getModule());
		Assertions.assertEquals(rule.getName(), importedRule.getName());
		Assertions.assertEquals(rule.getPriority(), importedRule.getPriority());
		Assertions.assertEquals(rule.toDto().getRuleDesignation(),
				importedRule.getRuleDesignation());

		Assertions.assertEquals(com.tracelink.appsec.watchtower.core.rule.RuleState.RETIRED,
				deprecatedRule.getStewardship().getState());
		BDDMockito.verify(mockRuleRepository).saveAndFlush(deprecatedRule);
		BDDMockito.verify(mockRuleRepository, BDDMockito.never()).delete(deprecatedRule);
		BDDMockito.verify(mockRulesetRepository).delete(deprecatedRuleset);
	}
}
