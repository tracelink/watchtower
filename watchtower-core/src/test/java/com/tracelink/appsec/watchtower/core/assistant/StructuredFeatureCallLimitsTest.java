package com.tracelink.appsec.watchtower.core.assistant;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import com.fasterxml.jackson.databind.node.ObjectNode;
import com.tracelink.appsec.watchtower.core.assistant.features.StructuredFeatureCall;

/** A feature can ask for larger bounds than the usual 8,000 in and 600 out; everything else keeps the usual ones. */
class StructuredFeatureCallLimitsTest {
	@TempDir
	Path dir;
	AssistantFixture fx;
	StructuredFeatureCall calls;
	final List<OpenAiLlmClient.Structured> sent = new ArrayList<>();

	static OpenAiLlmClient.StructuredReply reply() {
		return new OpenAiLlmClient.StructuredReply("{}", false, "completed", 1200, 60, true);
	}

	@BeforeEach
	void setUp() throws Exception {
		fx = new AssistantFixture(dir, Set.of("Assistant Use"));
		fx.configure(c -> AssistantFixture.slice(c, "ruleDraft", true, 500_000, 500_000));
		calls = new StructuredFeatureCall(fx.settings, R1Database.keys(fx.keyConfigured), fx.budgets, request -> {
			sent.add(request);
			return reply();
		});
	}

	@AfterEach
	void close() {
		fx.close();
	}

	private static ObjectNode schema() {
		return AssistantState.mapper().createObjectNode().put("type", "object");
	}

	@Test
	void theUsualBoundsApplyUnlessAFeatureAsksForOthers() {
		calls.ask("alice", AssistantFeature.RULE_DRAFT, "instructions", "input", "x", schema());
		calls.ask("alice", AssistantFeature.RULE_DRAFT, "instructions", "input", "x", schema(), 12000, 3500);

		assertEquals(StructuredFeatureCall.MAX_OUTPUT_TOKENS, sent.get(0).maxOutputTokens());
		assertEquals(3500, sent.get(1).maxOutputTokens());
	}

	@Test
	void aRequestOverTheFeaturesOwnInputBoundIsRefusedBeforeAnythingIsSent() {
		String big = "x".repeat(9000);

		assertThrows(IllegalArgumentException.class, () -> calls.ask("alice", AssistantFeature.RULE_DRAFT, "i", big, "x", schema()),
				"over the usual input bound");
		calls.ask("alice", AssistantFeature.RULE_DRAFT, "i", big, "x", schema(), 12000, 3500);
		assertEquals(1, sent.size(), "only the request inside its own bound was sent");
		assertThrows(IllegalArgumentException.class,
				() -> calls.ask("alice", AssistantFeature.RULE_DRAFT, "i", "x".repeat(13000), "x", schema(), 12000, 3500));
		assertEquals(1, sent.size());
	}

	@Test
	void theLargerAnswerIsCheckedAgainstTheDailyShareFirst() throws Exception {
		calls.requireAffordable("alice", AssistantFeature.RULE_DRAFT, 12000, 3500);
		fx.configure(c -> AssistantFixture.slice(c, "ruleDraft", true, 100, 100));

		var refused = assertThrows(org.springframework.web.server.ResponseStatusException.class,
				() -> calls.requireAffordable("alice", AssistantFeature.RULE_DRAFT, 12000, 3500));
		assertTrue(refused.getReason().contains("rule drafts"));
	}
}
