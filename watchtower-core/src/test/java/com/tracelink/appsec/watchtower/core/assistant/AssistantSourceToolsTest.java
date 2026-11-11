package com.tracelink.appsec.watchtower.core.assistant;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;
import java.io.IOException;
import java.nio.file.*;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.data.domain.PageImpl;
import org.springframework.security.access.AccessDeniedException;
import com.tracelink.appsec.watchtower.core.process.*;
import com.tracelink.appsec.watchtower.core.rule.*;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetService;
import com.tracelink.appsec.watchtower.core.metrics.RuleHealthService;
import com.tracelink.appsec.watchtower.core.feedback.MissedVulnerabilityService;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.*;
import com.tracelink.appsec.watchtower.core.scan.code.scm.api.*;
import com.tracelink.appsec.watchtower.core.scan.repository.*;

class AssistantSourceToolsTest {
    @TempDir Path dir;
    final String commit = "a".repeat(40);
    AssistantAccess access; RepositoryRepository repos; ApiIntegrationService integrations;
    IScmApi api; ProcessRunner processes; AssistantSourceTools source; AssistantToolRegistry tools; AssistantSecretFindings secrets;
    @BeforeEach void setup() throws Exception {
        access = mock(AssistantAccess.class); repos = mock(RepositoryRepository.class); integrations = mock(ApiIntegrationService.class);
        api = mock(IScmApi.class); processes = mock(ProcessRunner.class);
        var repo = mock(RepositoryEntity.class); when(repo.getId()).thenReturn(42L); when(repo.getApiLabel()).thenReturn("fixture"); when(repo.getRepoName()).thenReturn("example");
        when(repos.findById(42L)).thenReturn(Optional.of(repo)); when(repos.findAll(any(org.springframework.data.domain.Pageable.class))).thenReturn(new PageImpl<>(List.of(repo)));
        var integration = mock(ApiIntegrationEntity.class); when(integration.createApi()).thenReturn(api); when(integrations.findByLabel("fixture")).thenReturn(integration);
        var grants = new HashSet<>(AssistantSourceTools.GRANTS); grants.add("Assistant Use"); when(access.authorities(anyString())).thenReturn(grants);
        secrets = mock(AssistantSecretFindings.class); when(secrets.lines(any())).thenReturn(new AssistantSecretFindings.Lines(Map.of()));
        source = new AssistantSourceTools(access, repos, integrations, processes, secrets, "/trusted/python3", dir.toString());
        tools = new AssistantToolRegistry(access, mock(RuleService.class), mock(RulesetService.class), mock(RuleHealthService.class), mock(RuleReviewService.class), mock(com.tracelink.appsec.watchtower.core.persistence.LedgerRepository.class), source, secrets);
        doAnswer(invocation -> { Path root = invocation.getArgument(2); Files.createDirectories(root.resolve("app"));
            Files.writeString(root.resolve("app/sample.py"), "def greet():\n    token='private-value'\n    return greet()\n");
            Files.writeString(root.resolve(".env"), "credential=private-value"); return null;
        }).when(api).downloadSource(eq("example"), eq(commit), any(Path.class), eq(SourceDownloadLimits.ASSISTANT));
    }
    String args(String additional) { return "{\"repo_id\":42,\"commit\":\""+commit+"\""+additional+"}"; }
    void empty() throws Exception { try (var paths = Files.list(dir)) { assertEquals(0, paths.count()); } }

    @Test void pinsReadsSearchAndSyntaxUseFreshBoundedWorkspacesAndCleanEveryOperation() throws Exception {
        assertEquals("example", tools.invoke("engineer", "list_repositories", "{\"offset\":0}", 8192).path("data").path("repositories").get(0).path("repository").asText());
        when(api.getBranch("example", "main")).thenReturn(Optional.of(new ScmBranch("main", commit, 0)));
        assertEquals(commit, tools.invoke("engineer", "resolve_repository_commit", "{\"repo_id\":42,\"branch\":\"main\"}", 8192).path("data").path("commit").asText());
        var read = tools.invoke("engineer", "read_source_file", args(",\"path\":\"app/sample.py\",\"start_line\":1,\"line_count\":3"), 8192);
        assertEquals("before\n[REDACTED]\n\n\nafter", AssistantText.redactSource("before\n-----BEGIN PRIVATE KEY-----\nprivate-value\n-----END PRIVATE KEY-----\nafter"));
        assertTrue(read.toString().contains("[REDACTED]")); assertFalse(read.toString().contains("private-value")); empty();
        var listing = tools.invoke("engineer", "list_source_files", args(",\"offset\":0"), 8192);
        assertFalse(listing.toString().contains(".env\"")); empty();
        var found = tools.invoke("engineer", "search_source", args(",\"query\":\"greet\""), 8192);
        assertEquals(2, found.path("data").path("evidence").path("matches").size()); empty();
        when(processes.run(any())).thenAnswer(invocation -> { ProcessRequest request = invocation.getArgument(0);
            assertTrue(request.environment().isEmpty()); assertTrue(request.command().contains("-I")); assertEquals(Duration.ofSeconds(10), request.timeout());
            assertTrue(Files.exists(Path.of(request.command().get(3))));
            return new ProcessResult(0, "{\"parser_version\":\"0.25.2\",\"approximate\":true,\"syntax_errors\":false,\"entries\":[]}", "", false, false, false, Duration.ZERO);
        });
        assertTrue(tools.invoke("engineer", "source_outline", args(",\"path\":\"app/sample.py\""), 8192).path("data").path("evidence").path("approximate").asBoolean()); empty();
        tools.invoke("engineer", "source_references", args(",\"path\":\"app/sample.py\",\"symbol\":\"greet\""), 8192); empty();
        verify(api, times(5)).downloadSource(eq("example"), eq(commit), any(Path.class), eq(SourceDownloadLimits.ASSISTANT));
        var state = new AssistantState(); state.promptVersion = "r1-v1"; state.toolVersion = "r1-v1";
        var restored = AssistantState.decode(state.encode(1024), 1024); assertEquals("r1-v1", restored.promptVersion);
        assertFalse(tools.schemas("engineer", restored.toolVersion).toString().contains("read_source_file"));
        state.promptVersion="r2-v1";state.toolVersion="r2-v1";var r2=AssistantState.decode(state.encode(1024),1024);
        assertEquals("r2-v1",r2.promptVersion);assertFalse(tools.schemas("engineer",r2.toolVersion).toString().contains("get_rule_candidates"));
        restored.user("Continue"); assertEquals(AssistantState.PROMPT_VERSION, restored.promptVersion);
    }
    @Test void linesWhereAnyEngineRecordedASecretNeverLeaveAndUncheckableSourceIsWithheld() throws Exception {
        when(secrets.lines(any())).thenReturn(new AssistantSecretFindings.Lines(Map.of("app/sample.py", Map.of(2, "Betterleaks"))));
        var read = tools.invoke("engineer", "read_source_file", args(",\"path\":\"app/sample.py\",\"start_line\":1,\"line_count\":3"), 8192).toString();
        assertTrue(read.contains("[REDACTED: secret detected by Betterleaks]")); assertFalse(read.contains("token")); assertTrue(read.contains("def greet()")); empty();
        // Equivalent spellings of the path cannot dodge the mask: they are refused, and each workspace is cleaned.
        for (String spelling : List.of("app/./sample.py", "app//sample.py", "./app/sample.py"))
            assertThrows(IllegalArgumentException.class, () -> tools.invoke("engineer", "read_source_file", args(",\"path\":\""+spelling+"\",\"start_line\":1,\"line_count\":3"), 8192), spelling);
        empty();
        var found = tools.invoke("engineer", "search_source", args(",\"query\":\"private-value\""), 8192);
        assertEquals(0, found.path("data").path("evidence").path("matches").size(), "a secret line cannot confirm a guessed value"); empty();
        when(processes.run(any())).thenReturn(new ProcessResult(0, "{\"approximate\":true,\"entries\":[{\"name\":\"greet\",\"line\":1},{\"name\":\"token\",\"line\":2}]}", "", false, false, false, Duration.ZERO));
        var outline = tools.invoke("engineer", "source_outline", args(",\"path\":\"app/sample.py\""), 8192).path("data").path("evidence").path("entries");
        assertEquals(1, outline.size()); assertEquals("greet", outline.get(0).path("name").asText()); empty();
        when(secrets.lines(any())).thenThrow(new AssistantSecretFindings.Unavailable("Recorded secret findings are unavailable"));
        assertThrows(IllegalArgumentException.class, () -> tools.invoke("engineer", "read_source_file", args(",\"path\":\"app/sample.py\",\"start_line\":1,\"line_count\":3"), 8192));
        verify(api, times(6)).downloadSource(eq("example"), eq(commit), any(Path.class), eq(SourceDownloadLimits.ASSISTANT));
    }
    @Test void assessmentWindowsAreBoundedMaskedAndFlagASecretTargetLine() throws Exception {
        var repo = repos.findById(42L).orElseThrow();
        var window = source.window("engineer", repo, commit, "app/sample.py", 2, 1);
        assertEquals(1, window.first()); assertEquals(3, window.lines().size()); assertFalse(window.targetLineMasked());
        assertTrue(window.lines().toString().contains("[REDACTED]"), "generic secret patterns still apply"); empty();
        when(secrets.lines(any())).thenReturn(new AssistantSecretFindings.Lines(Map.of("app/sample.py", Map.of(2, "Betterleaks"))));
        var masked = source.window("engineer", repo, commit, "app/sample.py", 2, 1);
        assertTrue(masked.targetLineMasked()); assertFalse(masked.lines().toString().contains("token")); empty();
        assertThrows(IllegalArgumentException.class, () -> source.window("engineer", repo, commit, "app/sample.py", 99, 1), "a line outside the file is refused"); empty();
        assertThrows(IllegalArgumentException.class, () -> source.window("engineer", repo, "HEAD", "app/sample.py", 2, 1));
        assertThrows(IllegalArgumentException.class, () -> source.window("engineer", repo, commit, "app/sample.py", 2, 101));
    }
    @Test void approvedKnowledgeIsAReadToolOfTheR5ProtocolOnly() throws Exception {
        var rules = mock(RuleService.class); var entity = mock(RuleEntity.class); var dto = mock(RuleDto.class); var stewardship = new RuleStewardship(); stewardship.setCwe("CWE-79");
        when(rules.getRule(7L)).thenReturn(entity); when(entity.toDto()).thenReturn(dto); when(dto.getId()).thenReturn(7L); when(dto.getStewardship()).thenReturn(stewardship);
        var grants = new HashSet<>(AssistantSourceTools.GRANTS); grants.addAll(Set.of("Assistant Use", "Ruleset View", "Rule Modify")); when(access.authorities(anyString())).thenReturn(grants);
        var registry = new AssistantToolRegistry(access, rules, mock(RulesetService.class), mock(RuleHealthService.class), mock(RuleReviewService.class), mock(com.tracelink.appsec.watchtower.core.persistence.LedgerRepository.class), source, secrets);
        var knowledge = mock(com.tracelink.appsec.watchtower.core.rule.knowledge.KnowledgeService.class); registry.setKnowledge(knowledge);
        assertTrue(registry.schemas("engineer", "r5-v1").toString().contains("get_approved_knowledge"));
        assertTrue(registry.schemas("engineer", "r5-v1").toString().contains("get_rule_candidates"), "R3 tools stay available in r5-v1");
        assertFalse(registry.schemas("engineer", "r3-v1").toString().contains("get_approved_knowledge"), "older conversations keep their recorded tools");
        when(knowledge.applicable(7L, "CWE-79", 42L, "java")).thenReturn(List.of(Map.of("id", "k1", "statement", "Encode.forHtml escapes HTML output")));
        var found = registry.invoke("engineer", "get_approved_knowledge", "{\"rule_id\":7,\"repository_id\":42,\"language\":\"java\"}", 8192).toString();
        assertTrue(found.contains("Encode.forHtml")); assertTrue(found.contains("only inside its scope"));
        var none = registry.invoke("engineer", "get_approved_knowledge", "{\"rule_id\":7,\"repository_id\":0,\"language\":\"java\"}", 8192).toString();
        assertTrue(none.contains("uncertain")); verify(knowledge).applicable(7L, "CWE-79", null, "java");
        assertTrue(OpenAiLlmClient.R5_INSTRUCTIONS.contains("get_approved_knowledge")); assertFalse(OpenAiLlmClient.R5_INSTRUCTIONS.contains("knowledge is configured"));
        assertTrue(OpenAiLlmClient.R3_INSTRUCTIONS.contains("knowledge is configured"), "r3-v1 conversations keep their original instructions");
        var r3 = new AssistantState(); r3.promptVersion = "r3-v1"; r3.toolVersion = "r3-v1"; assertEquals("r3-v1", AssistantState.decode(r3.encode(1024), 1024).promptVersion);
        assertEquals("actions-v1", AssistantState.PROMPT_VERSION);
    }
    @Test void humanTextAboutSecretRulesIsWithheldFromEveryFeedbackTool() throws Exception {
        var rules = mock(RuleService.class); var entity = mock(RuleEntity.class); var dto = mock(RuleDto.class);
        when(rules.getRule(5L)).thenReturn(entity); when(entity.toDto()).thenReturn(dto); when(dto.getId()).thenReturn(5L);
        var records = mock(com.tracelink.appsec.watchtower.core.persistence.LedgerRepository.class); var reviews = mock(RuleReviewService.class);
        when(records.maps(contains("FindingFeedbackEntity"), anyInt(), anyInt(), any())).thenReturn(List.of(Map.of("judgment", "FALSE_POSITIVE", "explanation", "the key TLK-INT-9f2a is a test key")));
        when(records.maps(contains("PullRequestBypassEntity"), anyInt(), anyInt(), any())).thenReturn(List.of(Map.of("bypass_id", 1L, "reason", "TLK-INT-9f2a is fake"), Map.of("bypass_id", 2L, "reason", "generated code")));
        when(reviews.list(5L, 0)).thenReturn(List.of(Map.of("status", "REJECTED", "outcome", "value TLK-INT-9f2a rotated")));
        var grants = new HashSet<>(AssistantSourceTools.GRANTS); grants.addAll(Set.of("Assistant Use", "Ruleset View")); when(access.authorities(anyString())).thenReturn(grants);
        var registry = new AssistantToolRegistry(access, rules, mock(RulesetService.class), mock(RuleHealthService.class), reviews, records, source, secrets);
        when(secrets.isSecretRule(dto)).thenReturn(true);
        for (String tool : List.of("get_finding_feedback", "get_bypass_reasons")) {
            var result = registry.invoke("engineer", tool, "{\"rule_id\":5}", 8192).toString();
            assertFalse(result.contains("TLK-INT"), tool); assertTrue(result.contains(AssistantSecretFindings.WITHHELD), tool);
        }
        var reviewed = registry.invoke("engineer", "get_rule_reviews", "{\"rule_id\":5,\"offset\":0}", 8192).toString();
        assertFalse(reviewed.contains("TLK-INT")); assertTrue(reviewed.contains("REJECTED"));
        // Not a secret rule, but bypass 1 also covered a Betterleaks finding: only that reason is withheld.
        when(secrets.isSecretRule(dto)).thenReturn(false); when(secrets.bypassesCoveringSecrets(any(), any())).thenReturn(Set.of(1L));
        var bypasses = registry.invoke("engineer", "get_bypass_reasons", "{\"rule_id\":5}", 8192).toString();
        assertFalse(bypasses.contains("TLK-INT")); assertTrue(bypasses.contains("generated code"));
    }
    @Test void rejectsUnsafePathsRevokedScopeMissingPinsAndInterruptedWorkspaceArtifacts() throws Exception {
        for (String path : List.of("/etc/passwd", "../outside", "app/../../outside", ".env", "app\\sample.py", "C:/sample.py")) {
            assertThrows(IllegalArgumentException.class, () -> tools.invoke("engineer", "read_source_file", args(",\"path\":\""+path.replace("\\","\\\\")+"\",\"start_line\":1,\"line_count\":1"), 8192)); empty();
        }
        assertThrows(IllegalArgumentException.class, () -> tools.invoke("engineer", "source_outline", "{\"repo_id\":42,\"commit\":\"HEAD\",\"path\":\"app/sample.py\"}", 8192));
        assertThrows(AccessDeniedException.class, () -> tools.invoke("engineer", "list_source_files", args(",\"offset\":0").replace("42", "99"), 8192));
        doThrow(new IOException("Missing pin")).when(api).downloadSource(eq("example"), eq(commit), any(Path.class), any());
        assertThrows(IllegalArgumentException.class, () -> tools.invoke("engineer", "list_source_files", args(",\"offset\":0"), 8192)); empty();
        verify(api, never()).getBranch(anyString(), anyString());
        var revoked = new AtomicBoolean();
        doAnswer(i -> { if (revoked.get()) throw new AccessDeniedException("Revoked"); return null; }).when(access).require(eq("engineer"), anyString());
        when(api.getBranch("example", "main")).thenAnswer(i -> { revoked.set(true); return Optional.of(new ScmBranch("main", commit, 0)); });
        assertThrows(AccessDeniedException.class, () -> tools.invoke("engineer", "resolve_repository_commit", "{\"repo_id\":42,\"branch\":\"main\"}", 8192));
        revoked.set(false);
        doAnswer(i -> { Path root = i.getArgument(2); Files.createDirectories(root); revoked.set(true); return null; }).when(api).downloadSource(eq("example"), eq(commit), any(Path.class), any());
        assertThrows(AccessDeniedException.class, () -> tools.invoke("engineer", "list_source_files", args(",\"offset\":0"), 8192)); empty();
        var state = new AssistantState(); state.evidence.addObject().put("name", "list_source_files").set("arguments", AssistantState.mapper().readTree(args(",\"offset\":0")));
        assertThrows(AccessDeniedException.class, () -> tools.replay("engineer", state));
        Path stale = Files.createDirectories(dir.resolve("request-stale")); Files.writeString(stale.resolve("source.txt"), "temporary"); Files.setLastModifiedTime(stale, java.nio.file.attribute.FileTime.fromMillis(0));
        Path recent = Files.createDirectories(dir.resolve("request-recent")); source.cleanup(); assertFalse(Files.exists(stale)); assertTrue(Files.exists(recent));
    }
    @Test void confirmedMissesPersistWithoutAnExistingRuleAndDoNotBecomeHealthLabels() {
        try(var database = new R1Database()) { var reviews = mock(RuleReviewService.class);
        var service = database.service(new MissedVulnerabilityService(database.records, source, repos, reviews, access));
        var input = new MissedVulnerabilityService.Intake(42,commit,"b".repeat(40),"app/sample.py",3,"PENTEST","pentest/report-42","CWE-79",null,null,"fixtures/xss/positive-v1.py","c".repeat(64),"python","unknown","unknown");
        assertNotNull(service.save(input,"engineer")); assertEquals(1,service.list(42,0,"engineer").size());
        assertNull(service.list(42,0,"engineer").getFirst().get("rule_id"));
        assertEquals(0,database.jdbc.queryForObject("SELECT COUNT(*) FROM finding_feedback",Integer.class)); verifyNoInteractions(reviews);
        var invalid = new MissedVulnerabilityService.Intake(42,"HEAD",null,"app/sample.py",3,"PENTEST","pentest/report-42","CWE-79",null,null,"fixtures/xss/positive-v1.py","c".repeat(64),"python","unknown","unknown");
        assertThrows(IllegalArgumentException.class, () -> service.save(invalid,"engineer"));
        }
    }
}
