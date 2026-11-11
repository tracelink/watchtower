package com.tracelink.appsec.watchtower.core.rule;

import static org.junit.jupiter.api.Assertions.*;

import java.util.List;
import java.util.Set;

import org.junit.jupiter.api.Test;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.tracelink.appsec.watchtower.core.mock.MockCustomRuleDto;
import com.tracelink.appsec.watchtower.core.mock.MockRuleEntity;
import com.tracelink.appsec.watchtower.core.scan.code.report.CodeScanViolation;

class RuleRevisionTest {

	@Test
	void canonicalOrderingAndFraming() {
		String first = RuleRevision.definition("regex", "CUSTOM").field("pattern", "a\nb:é")
				.unordered("parameters", List.of("b", "a")).hash();
		String reordered = RuleRevision.definition("regex", "CUSTOM")
				.unordered("parameters", List.of("a", "b")).field("pattern", "a\nb:é").hash();
		assertEquals(first, reordered);
		assertTrue(first.matches("[0-9a-f]{64}"));
		assertNotEquals(RuleRevision.definition("x", "y").field("a", "b\nc").field("d", "e").hash(),
				RuleRevision.definition("x", "y").field("a", "b").field("c\nd", "e").hash());
		assertNotEquals(RuleRevision.definition("x", "y").field("a", null).hash(),
				RuleRevision.definition("x", "y").field("a", "").hash());
		assertNotEquals(RuleRevision.definition("x", "y").unordered("a", null).hash(),
				RuleRevision.definition("x", "y").unordered("a", List.of()).hash());
		assertThrows(IllegalArgumentException.class,
				() -> RuleRevision.definition("x", "y").field("module", "override"));
	}

	@Test
	void unknownDefinitionDoesNotTrustImportedOrLegacyRevision() {
		MockCustomRuleDto rule = new MockCustomRuleDto();
		rule.setName("legacy");
		rule.getStewardship().setRevision("a".repeat(64));
		assertNull(rule.getRevision());
		assertNull(rule.getExecutionIdentity().revision());
		assertNull(rule.getExecutionIdentity().ruleId());
		assertEquals(RuleExecutionIdentity.unmanaged("PMD", "external").module(), "pmd");
	}

	@Test
	void identityIsImmutableAndIndependentOfNameBasedDtoEquality() {
		DefinitionRule rule = new DefinitionRule();
		rule.setId(42L);
		rule.setName("name");
		rule.getStewardship().setOriginKey("upstream:abc");
		RuleExecutionIdentity original = rule.getExecutionIdentity();
		CodeScanViolation violation = new CodeScanViolation();
		violation.setRuleIdentity(original);
		rule.pattern = "changed";
		RuleExecutionIdentity changed = rule.getExecutionIdentity();
		assertNotEquals(original.revision(), changed.revision());
		assertEquals(original, violation.getRuleIdentity());
		assertEquals(2, Set.of(original, changed).size());
		assertEquals(42L, original.ruleId());
		assertEquals("upstream:abc", original.originKey());
		rule.setName("renamed");
		rule.setPriority(RulePriority.LOW);
		rule.getStewardship().setOwner("new owner");
		assertEquals(changed, rule.getExecutionIdentity());
		assertThrows(IllegalArgumentException.class,
				() -> new RuleExecutionIdentity(0L, "regex", null, null, null));
		assertThrows(IllegalArgumentException.class,
				() -> new RuleExecutionIdentity(1L, "regex", "not-a-hash", null, null));
	}

	@Test
	void revisionAndIdentityDoNotChangeRuleExportContract() throws Exception {
		DefinitionRule rule = new DefinitionRule();
		rule.setName("test");
		rule.getStewardship().setOwner("security-team");
		rule.getStewardship().setState(RuleState.RETIRED);
		var json = new ObjectMapper().valueToTree(rule);
		assertFalse(json.has("revision"));
		assertFalse(json.has("executionIdentity"));
		assertFalse(json.has("externalRuleKey"));
		assertFalse(json.has("stewardship"));
		assertFalse(json.toString().contains("security-team"));
		assertFalse(json.toString().contains("retired"));
		CodeScanViolation legacy = new ObjectMapper().readValue("{\"violationName\":\"old\"}",
				CodeScanViolation.class);
		assertNull(legacy.getRuleIdentity());
		CodeScanViolation current = new CodeScanViolation();
		current.setRuleIdentity(rule.getExecutionIdentity());
		ObjectMapper mapper = new ObjectMapper();
		assertEquals(current.getRuleIdentity(), mapper.readValue(mapper.writeValueAsString(current),
				CodeScanViolation.class).getRuleIdentity());
	}

	@Test
	void lifecycleWritesCurrentRevisionWithoutInventingLegacyCreationDate() {
		DefinitionEntity entity = new DefinitionEntity();
		assertNull(entity.getStewardship().getCreatedAt());
		assertNull(entity.getStewardship().getRevision());
		String current = entity.toDto().getRevision();
		entity.recordUpdate();
		assertEquals(current, entity.getStewardship().getRevision());
		assertNull(entity.getStewardship().getCreatedAt());
		entity.pattern = "changed";
		entity.recordUpdate();
		assertNotEquals(current, entity.getStewardship().getRevision());
		entity.recordCreation();
		assertNotNull(entity.getStewardship().getCreatedAt());
	}

	private static class DefinitionRule extends MockCustomRuleDto {
		private String pattern = "initial";

		@Override
		protected RuleRevision executableDefinition() {
			return newDefinition().field("pattern", pattern);
		}
	}

	private static class DefinitionEntity extends MockRuleEntity {
		private String pattern = "initial";

		@Override
		public RuleDto toDto() {
			DefinitionRule dto = new DefinitionRule();
			dto.setName(getName());
			dto.pattern = pattern;
			return withStewardship(dto);
		}
	}
}
