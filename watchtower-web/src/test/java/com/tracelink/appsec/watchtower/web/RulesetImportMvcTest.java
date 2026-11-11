package com.tracelink.appsec.watchtower.web;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.multipart;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.UserRequestPostProcessor;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.tracelink.appsec.module.regex.model.RegexCustomRuleDto;
import com.tracelink.appsec.watchtower.core.rule.RulePriority;
import com.tracelink.appsec.watchtower.core.rule.RuleRepository;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetDesignation;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetRepository;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetService;

/**
 * Ruleset import (UAT #26): a preview that writes nothing, and an import that is all or nothing.
 * Not @Transactional on purpose, so the service's own transaction boundary is what is tested.
 */
@SpringBootTest(properties = {"watchtower.runAfterStartup=false", "watchtower.rule-testing.enabled=false",
		"spring.datasource.url=jdbc:h2:mem:uat-import;MODE=MySQL;DB_CLOSE_DELAY=-1;DB_CLOSE_ON_EXIT=FALSE"})
@AutoConfigureMockMvc
@ActiveProfiles("dev")
class RulesetImportMvcTest {
	private static final String PREFIX = "ImportFixture";

	@MockitoBean
	com.tracelink.appsec.watchtower.web.dev.DevelopmentSetup developmentSetup;
	@Autowired
	MockMvc mvc;
	@Autowired
	RuleRepository rules;
	@Autowired
	RulesetRepository rulesets;
	@Autowired
	RulesetService rulesetService;

	private final UserRequestPostProcessor admin = user("admin").authorities(() -> "Ruleset Import/Export",
			() -> "Ruleset View", () -> "Ruleset Modify");
	private final ObjectMapper json = new ObjectMapper();
	private long rulesetId;

	@BeforeEach
	void seed() throws Exception {
		var dto = new RegexCustomRuleDto();
		dto.setName(PREFIX + " rule");
		dto.setAuthor("reviewer");
		dto.setMessage("Import match");
		dto.setExternalUrl("https://example.test/rule");
		dto.setPriority(RulePriority.HIGH);
		dto.setRegexPattern("unsafe");
		dto.setFileExtension("");
		var rule = rules.saveAndFlush(dto.toEntity());
		var ruleset = rulesetService.createRuleset(PREFIX + " ruleset", "Fixture", RulesetDesignation.SUPPORTING);
		// Attach directly: RuleService resolves ids through a cache that has not seen this rule yet.
		ruleset.setRules(new java.util.HashSet<>(java.util.Set.of(rule)));
		rulesetId = rulesets.saveAndFlush(ruleset).getId();
	}

	@AfterEach
	void clean() throws Exception {
		for (var ruleset : rulesets.findAll()) {
			if (ruleset.getName().startsWith(PREFIX)) {
				rulesetService.deleteRuleset(ruleset.getId());
			}
		}
		rules.findAll().stream().filter(rule -> rule.getName().startsWith(PREFIX)).forEach(rules::delete);
	}

	private ObjectNode exported() throws Exception {
		String body = mvc.perform(post("/rulesets/" + rulesetId + "/export").with(admin).with(csrf()))
				.andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
		return (ObjectNode) json.readTree(body);
	}

	/** Exports use Jackson default typing ([class, value] arrays), so find the first rule object. */
	private static ObjectNode firstRule(com.fasterxml.jackson.databind.JsonNode node) {
		if (node instanceof ObjectNode object && object.has("name")) {
			return object;
		}
		for (var child : node) {
			ObjectNode found = firstRule(child);
			if (found != null) {
				return found;
			}
		}
		return null;
	}

	private static MockMultipartFile file(Object content) throws Exception {
		return new MockMultipartFile("file", "export.json", "application/json",
				new ObjectMapper().writeValueAsString(content).getBytes(StandardCharsets.UTF_8));
	}

	@Test
	void previewDescribesChangesWithoutWriting() throws Exception {
		ObjectNode export = exported();
		firstRule(export.get("rules")).put("name", PREFIX + " new rule");

		mvc.perform(multipart("/rulesets/" + rulesetId + "/import/preview").file(file(export)).with(admin).with(csrf()))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.existingRuleset").value(true))
				.andExpect(jsonPath("$.newRules").value(1))
				.andExpect(jsonPath("$.removedFromRuleset[0]").value(PREFIX + " rule"))
				.andExpect(jsonPath("$.problems").isEmpty());
		Assertions.assertNull(rules.findByName(PREFIX + " new rule"), "a preview never writes");

		mvc.perform(multipart("/rulesets/import/preview")
				.file(new MockMultipartFile("file", "x.json", "application/json", "not json".getBytes()))
				.with(admin).with(csrf()))
				.andExpect(status().isBadRequest())
				.andExpect(jsonPath("$.error").value(org.hamcrest.Matchers.containsString("Watchtower ruleset export")));
		mvc.perform(multipart("/rulesets/import/preview").file(file(export))
				.with(user("viewer").authorities(() -> "Ruleset View")).with(csrf()))
				.andExpect(status().isForbidden());
	}

	@Test
	void failedImportLeavesNoPartialRules() throws Exception {
		ObjectNode export = exported();
		export.put("name", PREFIX + " rollback");
		// Too long for the ruleset column: fails when the ruleset is saved, after its rules were written.
		export.put("description", "d".repeat(300));
		firstRule(export.get("rules")).put("name", PREFIX + " rollback rule");

		mvc.perform(multipart("/rulesets/import").file(file(export)).with(admin).with(csrf()))
				.andExpect(status().is3xxRedirection());

		Assertions.assertNull(rules.findByName(PREFIX + " rollback rule"), "the failed import must not keep new rules");
		Assertions.assertNull(rulesets.findByName(PREFIX + " rollback"));
	}
}
