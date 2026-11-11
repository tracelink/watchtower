package com.tracelink.appsec.watchtower.core.assistant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.security.access.AccessDeniedException;

import com.fasterxml.jackson.databind.node.ObjectNode;
import com.tracelink.appsec.watchtower.core.assistant.features.KnowledgeDraftService;
import com.tracelink.appsec.watchtower.core.assistant.features.KnowledgeDraftService.Ref;
import com.tracelink.appsec.watchtower.core.assistant.features.StructuredFeatureCall;
import com.tracelink.appsec.watchtower.core.cwe.CweCatalogService;
import com.tracelink.appsec.watchtower.core.persistence.FindingFeedbackEntity;
import com.tracelink.appsec.watchtower.core.persistence.LedgerRepository;
import com.tracelink.appsec.watchtower.core.persistence.MissedVulnerabilityCaseEntity;
import com.tracelink.appsec.watchtower.core.persistence.RuleReviewItemEntity;
import com.tracelink.appsec.watchtower.core.rule.RuleDto;
import com.tracelink.appsec.watchtower.core.rule.RuleEntity;
import com.tracelink.appsec.watchtower.core.rule.RuleService;
import com.tracelink.appsec.watchtower.core.rule.RuleStewardship;

/** The assistant drafts a Knowledge proposal's fields: what it is shown, what it may fill in, and what is refused. */
class KnowledgeDraftServiceTest {
	private static final String STATEMENT = "Encode.forHtml escapes HTML output, so it makes a value safe for an HTML body.";
	private StructuredFeatureCall calls;
	private AssistantAccess access;
	private LedgerRepository records;
	private RuleService rules;
	private AssistantSecretFindings secrets;
	private CweCatalogService catalog;
	private RuleDto dto;
	private KnowledgeDraftService service;

	@BeforeEach
	void setUp() throws Exception {
		calls = mock(StructuredFeatureCall.class);
		access = mock(AssistantAccess.class);
		records = mock(LedgerRepository.class);
		rules = mock(RuleService.class);
		secrets = mock(AssistantSecretFindings.class);
		catalog = mock(CweCatalogService.class);
		when(calls.readiness(AssistantFeature.KNOWLEDGE_DRAFT)).thenReturn(new StructuredFeatureCall.Readiness(null, "Ready."));
		when(catalog.isLoaded()).thenReturn(true);
		for (String usable : List.of("CWE-79", "CWE-80", "CWE-81", "CWE-116")) {
			when(catalog.isUsable(usable)).thenReturn(true);
		}
		var rule = mock(RuleEntity.class);
		dto = mock(RuleDto.class);
		when(dto.getName()).thenReturn("Unescaped HTML output");
		when(rule.toDto()).thenReturn(dto);
		var stewardship = new RuleStewardship();
		stewardship.setCwe("CWE-79");
		when(rule.getStewardship()).thenReturn(stewardship);
		when(rules.getRule(7L)).thenReturn(rule);
		service = new KnowledgeDraftService(calls, access, records, rules, secrets, catalog);
	}

	private static String answer(String kind, String statement, String language, String library, String versions, String cwes) {
		return "{\"supported\":true,\"kind\":\"" + kind + "\",\"statement\":\"" + statement + "\",\"language\":\"" + language + "\",\"library\":\""
				+ library + "\",\"version_range\":\"" + versions + "\",\"cwes\":" + cwes + ",\"reason\":\"The review says so.\"}";
	}

	private void model(String reply) {
		when(calls.ask(anyString(), eq(AssistantFeature.KNOWLEDGE_DRAFT), anyString(), anyString(), anyString(), any(ObjectNode.class)))
				.thenReturn(Optional.ofNullable(reply));
	}

	private void review(String status, String recommendation) {
		var review = new RuleReviewItemEntity();
		review.reviewId = "r1";
		review.ruleId = 7L;
		review.status = status;
		review.recommendation = recommendation;
		review.outcome = "agreed";
		when(records.find(RuleReviewItemEntity.class, "r1")).thenReturn(review);
	}

	private void missed(String cwe) {
		var missed = new MissedVulnerabilityCaseEntity();
		missed.caseId = "m1";
		missed.repositoryName = "payments-api";
		missed.commitHash = "0123456789abcdef0123456789abcdef01234567";
		missed.affectedPath = "src/main/java/pay/Secret42Service.java";
		missed.cwe = cwe;
		missed.language = "Java";
		missed.framework = "Spring MVC";
		missed.frameworkVersion = "6.1";
		when(records.find(MissedVulnerabilityCaseEntity.class, "m1")).thenReturn(missed);
	}

	private static List<Ref> one(String type, String id) {
		return List.of(new Ref(type, id));
	}

	private String sentToTheModel() {
		var input = ArgumentCaptor.forClass(String.class);
		verify(calls).ask(eq("alice"), eq(AssistantFeature.KNOWLEDGE_DRAFT), anyString(), input.capture(), anyString(), any(ObjectNode.class));
		return input.getValue();
	}

	private void verifyNothingWasAsked() {
		verify(calls, never()).ask(anyString(), any(), anyString(), anyString(), anyString(), any(ObjectNode.class));
	}

	@Test
	@SuppressWarnings("unchecked")
	void anAcceptedReviewBecomesFormFieldsInTheShapeAProposalTakes() {
		review("ACCEPTED", "Treat Encode.forHtml as a sanitizer");
		model(answer("sanitizer", STATEMENT, "Java", "OWASP Java Encoder", "1.2.x", "[\"cwe-79\",\"CWE-116\",\"CWE-798\",\"nonsense\",\"CWE-4242\"]"));

		var result = service.draft("alice", one("review", "r1"));

		assertThat(result).containsEntry("state", "OK").containsEntry("reason", "The review says so.");
		var fields = (Map<String, Object>) result.get("fields");
		assertThat(fields).containsEntry("kind", "SANITIZER").containsEntry("statement", STATEMENT).containsEntry("language", "java")
				.containsEntry("library", "OWASP Java Encoder").containsEntry("version_range", "1.2.x");
		assertThat((List<String>) fields.get("cwes")).containsExactly("CWE-79", "CWE-116");
		verify(access).require("alice", "Assistant Use");
		verify(access).require("alice", "Rule Modify");
		verify(access, never()).require("alice", "Scan Results View");
		verify(calls).requireAffordable("alice", AssistantFeature.KNOWLEDGE_DRAFT);
	}

	@Test
	@SuppressWarnings("unchecked")
	void atMostThreeWeaknessesAreKeptAndTheOptionalFieldsMayStayEmpty() {
		review("ACCEPTED", "Treat Encode.forHtml as a sanitizer");
		model(answer("note", STATEMENT, "java", "", "", "[\"CWE-79\",\"CWE-80\",\"CWE-81\",\"CWE-116\"]"));

		var fields = (Map<String, Object>) service.draft("alice", one("review", "r1")).get("fields");

		assertThat((List<String>) fields.get("cwes")).containsExactly("CWE-79", "CWE-80", "CWE-81");
		assertThat(fields).containsEntry("library", "").containsEntry("version_range", "");
	}

	@Test
	void theModelIsToldWhichPlainValuesTheFormAcceptsAndTheExamplesItIsGivenAreAccepted() {
		review("ACCEPTED", "Treat Encode.forHtml as a sanitizer");
		model(answer("note", STATEMENT, "java", "", "", "[]"));

		service.draft("alice", one("review", "r1"));

		var instructions = ArgumentCaptor.forClass(String.class);
		verify(calls).ask(eq("alice"), eq(AssistantFeature.KNOWLEDGE_DRAFT), instructions.capture(), anyString(), anyString(), any(ObjectNode.class));
		assertThat(instructions.getValue()).contains("ONE plain product name").contains("never a list, commas, quotes or ampersands")
				.contains("Spring Framework").contains("1.2.x or >=2.0 <3");
		// What the prompt calls fine is fine, and what it forbids is refused: a list of products was why drafts were thrown away.
		assertThat(com.tracelink.appsec.watchtower.core.rule.knowledge.KnowledgeService.checkedDraft("note", STATEMENT, "java", "Spring Framework", ">=2.0 <3"))
				.containsEntry("library", "Spring Framework").containsEntry("version_range", ">=2.0 <3");
		assertThatThrownBy(() -> com.tracelink.appsec.watchtower.core.rule.knowledge.KnowledgeService.checkedDraft("note", STATEMENT, "java", "Spring, PMD", ""))
				.isInstanceOf(IllegalArgumentException.class).hasMessageContaining("Library is not usable");
	}

	@Test
	void theModelSeesTheRuleAndTheRecordedTextOnly() {
		review("ACCEPTED", "Treat Encode.forHtml as a sanitizer");
		model(answer("sanitizer", STATEMENT, "java", "", "", "[]"));

		service.draft("alice", one("review", "r1"));

		assertThat(sentToTheModel()).contains("Unescaped HTML output", "CWE-79", "Treat Encode.forHtml as a sanitizer", "agreed");
	}

	@Test
	@SuppressWarnings("unchecked")
	void aMissedCaseSendsNoRepositoryPathOrCommitAndFillsTheLanguageTheModelLeftBlank() {
		missed("CWE-79");
		model(answer("framework_guarantee", STATEMENT, "", "", "", "[]"));

		var result = service.draft("alice", one("missed_case", "m1"));

		assertThat(sentToTheModel()).contains("CWE-79", "Spring MVC", "6.1").doesNotContain("payments-api", "0123456789abcdef", "Secret42Service",
				"src/main");
		assertThat((Map<String, Object>) result.get("fields")).containsEntry("language", "java");
	}

	@Test
	void aFindingJudgmentNeedsTheRightToSeeScanResults() {
		var judgment = new FindingFeedbackEntity();
		judgment.occurrenceKey = "f1";
		judgment.ruleId = 7L;
		judgment.judgment = "FALSE_POSITIVE";
		judgment.disposition = "ACCEPTED";
		judgment.explanation = "The value is encoded by a filter before it reaches the page.";
		when(records.find(FindingFeedbackEntity.class, "f1")).thenReturn(judgment);
		model(answer("framework_guarantee", STATEMENT, "java", "", "", "[]"));

		assertThat(service.draft("alice", one("finding_feedback", "f1"))).containsEntry("state", "OK");

		verify(access).require("alice", "Scan Results View");
		assertThat(sentToTheModel()).contains("FALSE_POSITIVE", "encoded by a filter");
	}

	@Test
	void missingRightsStopEverythingBeforeAnythingIsRead() {
		doThrow(new AccessDeniedException("no")).when(access).require("alice", "Rule Modify");

		assertThatThrownBy(() -> service.draft("alice", one("review", "r1"))).isInstanceOf(AccessDeniedException.class);

		verify(records, never()).find(any(), any());
		verifyNothingWasAsked();
	}

	@Test
	void evidenceAboutASecretRuleIsNeverSent() {
		review("ACCEPTED", "Treat this as a sanitizer");
		when(secrets.isSecretRule(dto)).thenReturn(true);

		assertThat(service.draft("alice", one("review", "r1"))).containsEntry("state", "BLOCKED");

		verifyNothingWasAsked();
		verify(calls, never()).requireAffordable(anyString(), any());
	}

	@Test
	void aMissedCaseAboutASecretWeaknessIsNeverSent() {
		missed("CWE-798");

		assertThat(service.draft("alice", one("missed_case", "m1"))).containsEntry("state", "BLOCKED");

		verifyNothingWasAsked();
	}

	@Test
	void freeTextThatLooksLikeASecretIsWithheldButTheRestIsStillUsed() {
		review("ACCEPTED", "Use token a1b2c3d4e5f6 for the encoder");
		model(answer("note", STATEMENT, "java", "", "", "[]"));

		service.draft("alice", one("review", "r1"));

		assertThat(sentToTheModel()).doesNotContain("a1b2c3d4e5f6").contains("withheld", "Unescaped HTML output");
	}

	@Test
	void whenTheEvidenceOnlyDescribesOneFindingTheAnswerIsAnExplainedNoAndFillsNothing() {
		review("ACCEPTED", "Treat Encode.forHtml as a sanitizer");
		model("{\"supported\":false,\"kind\":\"note\",\"statement\":\"\",\"language\":\"\",\"library\":\"\",\"version_range\":\"\",\"cwes\":[],"
				+ "\"reason\":\"This only describes one finding.\"}");

		var result = service.draft("alice", one("review", "r1"));

		assertThat(result).containsEntry("state", "UNSUPPORTED").doesNotContainKey("fields");
		assertThat((String) result.get("message")).contains("does not support a general fact", "only describes one finding");
	}

	@Test
	void aDraftTheRealProposalCheckWouldRefuseIsNotShownAndTheModelsTextIsNotRepeated() {
		review("ACCEPTED", "Treat Encode.forHtml as a sanitizer");
		model(answer("sanitizer", "Call <script>alert(1)</script> to escape output safely", "java", "", "", "[]"));

		var result = service.draft("alice", one("review", "r1"));

		assertThat(result).containsEntry("state", "UNUSABLE").doesNotContainKey("fields");
		assertThat((String) result.get("message")).contains("not usable").doesNotContain("alert(1)");
	}

	@Test
	void anAnswerThatIsNotJsonOrIsMissingIsUnusable() {
		review("ACCEPTED", "Treat Encode.forHtml as a sanitizer");
		model("not json");
		assertThat(service.draft("alice", one("review", "r1"))).containsEntry("state", "UNUSABLE");
		model(null);
		assertThat(service.draft("alice", one("review", "r1"))).containsEntry("state", "UNUSABLE");
	}

	@Test
	void aFeatureThatIsOffExplainsWhyAndAsksNothing() {
		when(calls.readiness(AssistantFeature.KNOWLEDGE_DRAFT)).thenReturn(new StructuredFeatureCall.Readiness("OFF", "Knowledge drafts is off."));

		assertThat(service.draft("alice", one("review", "r1"))).containsEntry("state", "OFF").containsEntry("message", "Knowledge drafts is off.");

		verifyNothingWasAsked();
	}

	@Test
	void evidenceMustBeChosenWellFormedAndOfAnAcceptedKind() {
		review("OPEN", "Treat Encode.forHtml as a sanitizer");

		assertThatThrownBy(() -> service.draft("alice", List.of())).isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> service.draft("alice", null)).isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> service.draft("alice", one("bypass", "x"))).isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> service.draft("alice", one("review", " "))).isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> service.draft("alice", one("review", "x".repeat(65)))).isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> service.draft("alice", List.of(new Ref("review", "a"), new Ref("review", "b"), new Ref("review", "c"),
				new Ref("review", "d"), new Ref("review", "e"), new Ref("review", "f")))).isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> service.draft("alice", one("review", "r1"))).isInstanceOf(IllegalArgumentException.class)
				.hasMessageContaining("not an accepted one");
		assertThatThrownBy(() -> service.draft("alice", one("review", "gone"))).isInstanceOf(IllegalArgumentException.class);
	}
}
