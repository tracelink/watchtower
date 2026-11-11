package com.tracelink.appsec.watchtower.core.assistant.review;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.tuple;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicLong;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.web.server.ResponseStatusException;

import com.fasterxml.jackson.databind.node.ObjectNode;
import com.tracelink.appsec.watchtower.core.assistant.AssistantAccess;
import com.tracelink.appsec.watchtower.core.assistant.AssistantFeature;
import com.tracelink.appsec.watchtower.core.assistant.AssistantSourceTools;
import com.tracelink.appsec.watchtower.core.assistant.R1Database;
import com.tracelink.appsec.watchtower.core.assistant.features.RuleDraftSuggestService;
import com.tracelink.appsec.watchtower.core.assistant.features.StructuredFeatureCall;
import com.tracelink.appsec.watchtower.core.cwe.CweCatalogService;
import com.tracelink.appsec.watchtower.core.cwe.CweProfileService;
import com.tracelink.appsec.watchtower.core.job.AsyncJobService;
import com.tracelink.appsec.watchtower.core.job.AsyncJobType;
import com.tracelink.appsec.watchtower.core.rule.knowledge.KnowledgeService;
import com.tracelink.appsec.watchtower.core.scan.repository.RepositoryEntity;

/** An AI review of picked files: what is queued, what is asked, what is kept, and what stops it. */
class AiReviewServiceTest {
	private static final String COMMIT = "a".repeat(40);
	private static final long DAY = 24L * 60 * 60 * 1000;
	private final AtomicLong now = new AtomicLong(Instant.parse("2026-10-27T10:00:00Z").toEpochMilli());
	private R1Database database;
	private StructuredFeatureCall calls;
	private AssistantAccess access;
	private AssistantSourceTools source;
	private AiReviewScans scans;
	private CweCatalogService catalog;
	private CweProfileService profile;
	private KnowledgeService knowledge;
	private RuleDraftSuggestService drafts;
	private AsyncJobService jobs;
	private AiReviewRunRepository runs;
	private AiReviewFileRepository files;
	private AiReviewItemRepository items;
	private AiReviewService service;
	private AiReviewScans.Scan scan;

	@SuppressWarnings("unchecked")
	@BeforeEach
	void setUp() {
		database = new R1Database();
		calls = mock(StructuredFeatureCall.class);
		access = mock(AssistantAccess.class);
		source = mock(AssistantSourceTools.class);
		scans = mock(AiReviewScans.class);
		catalog = mock(CweCatalogService.class);
		profile = mock(CweProfileService.class);
		knowledge = mock(KnowledgeService.class);
		drafts = mock(RuleDraftSuggestService.class);
		jobs = mock(AsyncJobService.class);
		ObjectProvider<AsyncJobService> provider = mock(ObjectProvider.class);
		when(provider.getObject()).thenReturn(jobs);
		runs = database.repository(AiReviewRunRepository.class);
		files = database.repository(AiReviewFileRepository.class);
		items = database.repository(AiReviewItemRepository.class);
		when(calls.readiness(AssistantFeature.AI_CODE_REVIEW)).thenReturn(new StructuredFeatureCall.Readiness(null, "Ready."));
		when(catalog.isLoaded()).thenReturn(true);
		when(catalog.isUsable(anyString())).thenAnswer(invocation -> Set.of("CWE-89", "CWE-79", "CWE-22").contains(invocation.getArgument(0)));
		when(catalog.name("CWE-89")).thenReturn("SQL Injection");
		when(profile.list()).thenReturn(List.of(new CweProfileService.Entry(89, "CWE-89", "SQL Injection", "CRITICAL", null, true)));
		var repo = mock(RepositoryEntity.class);
		when(repo.getId()).thenReturn(42L);
		scan = new AiReviewScans.Scan("pull_request", 7, repo, COMMIT, null);
		when(scans.resolve("pull_request", 7)).thenReturn(scan);
		when(scans.pinned(anyString(), any())).thenAnswer(invocation -> invocation.getArgument(1));
		when(scans.findings(scan)).thenReturn(new AiReviewScans.Points(List.of(), true));
		Clock clock = new Clock() {
			@Override
			public java.time.ZoneId getZone() {
				return ZoneOffset.UTC;
			}

			@Override
			public Clock withZone(java.time.ZoneId zone) {
				return this;
			}

			@Override
			public Instant instant() {
				return Instant.ofEpochMilli(now.get());
			}
		};
		service = new AiReviewService(calls, access, source, scans, runs, files, items, catalog, profile, knowledge, drafts, provider, database.tx, clock);
	}

	@AfterEach
	void tearDown() {
		database.close();
	}

	// ---- helpers

	private static AssistantSourceTools.ReviewFile file(String path, int lines, Set<Integer> masked) {
		List<String> text = new ArrayList<>();
		for (int i = 1; i <= lines; i++) {
			text.add(masked.contains(i) ? "[REDACTED: secret detected by Betterleaks]" : "line " + i);
		}
		return new AssistantSourceTools.ReviewFile(path, text, lines, false, masked, null);
	}

	private void read(AssistantSourceTools.ReviewFile... read) {
		when(source.reviewFiles(anyString(), any(), eq(COMMIT), any(), anyInt(), anyInt())).thenReturn(List.of(read));
	}

	private void model(String... replies) {
		var stub = when(calls.ask(anyString(), eq(AssistantFeature.AI_CODE_REVIEW), anyString(), anyString(), anyString(), any(ObjectNode.class), anyInt(), anyInt()));
		for (String reply : replies) {
			stub = stub.thenReturn(Optional.ofNullable(reply));
		}
	}

	private static String item(int first, int last, String cwe, String confidence, String why) {
		return "{\"first_line\":" + first + ",\"last_line\":" + last + ",\"cwe\":\"" + cwe + "\",\"confidence\":\"" + confidence
				+ "\",\"rationale\":\"" + why + "\",\"suggested_scanner\":\"pmd\"}";
	}

	private static String answer(String... items) {
		return "{\"items\":[" + String.join(",", items) + "]}";
	}

	private String queued(String... paths) {
		var view = service.start("alice", "pull_request", 7, List.of(paths));
		return (String) view.get("run_id");
	}

	// ---- starting

	@Test
	void startingQueuesOneJobAndRemembersTheFilesButNeverTheirText() {
		String runId = queued("src/A.java", "./src/B.java", "src/A.java");

		var run = runs.findById(runId).orElseThrow();
		assertThat(run.getStatus()).isEqualTo("QUEUED");
		assertThat(run.getRequestedBy()).isEqualTo("alice");
		assertThat(run.getFilesTotal()).isEqualTo(2);
		assertThat(run.getExpiresAt()).isEqualTo(now.get() + 30 * DAY);
		assertThat(files.findByRunIdOrderByPath(runId)).extracting(AiReviewFileEntity::getPath).containsExactly("src/A.java", "src/B.java");
		verify(jobs).enqueue(AsyncJobType.AI_CODE_REVIEW, runId, "ai-code-review:" + runId, "alice");
		verify(access, org.mockito.Mockito.atLeastOnce()).require("alice", "Assistant Use");
		verify(source, never()).reviewFiles(anyString(), any(), anyString(), any(), anyInt(), anyInt());
	}

	@Test
	void aCommitThatCannotBeCompletedToAFullHashIsRefusedBeforeAnythingIsQueued() {
		when(scans.pinned(anyString(), any())).thenThrow(new IllegalArgumentException("The scanned commit could not be completed to a full hash by the source control system, so its files cannot be read."));

		assertThatThrownBy(() -> service.start("alice", "pull_request", 7, List.of("src/A.java"))).isInstanceOf(IllegalArgumentException.class)
				.hasMessageContaining("full hash");

		verify(jobs, never()).enqueue(any(), anyString(), anyString(), anyString());
		assertThat(runs.count()).isZero();
	}

	@Test
	void theFilesAreReadAtTheFullCommitEvenWhenTheScanRecordedAShortOne() {
		String shortCommit = "b".repeat(12);
		var shortScan = new AiReviewScans.Scan("pull_request", 7, scan.repository(), shortCommit, null);
		when(scans.resolve("pull_request", 7)).thenReturn(shortScan);
		when(scans.pinned(anyString(), any())).thenReturn(scan);
		when(scans.findings(scan)).thenReturn(new AiReviewScans.Points(List.of(), true));
		String runId = queued("src/A.java");
		read(file("src/A.java", 10, Set.of()));
		model(answer());

		service.run(runId, progress -> { });

		verify(source).reviewFiles(eq("alice"), any(), eq(COMMIT), any(), anyInt(), anyInt());
	}

	@Test
	void twoHundredFilesMayBeReviewedInOneRunAndOnlyTheLimitIsRefused() {
		var paths = new ArrayList<String>();
		for (int i = 0; i < 200; i++) {
			paths.add("src/F" + i + ".java");
		}

		var view = service.start("alice", "pull_request", 7, paths);

		assertThat(view).containsEntry("state", "QUEUED").containsEntry("files_total", 200);
		assertThat(files.findByRunIdOrderByPath((String) view.get("run_id"))).hasSize(200);
	}

	@Test
	void aFocusIsKeptWithTheRunAndSentToTheModelAsDataThatCannotChangeTheRules() {
		var view = service.start("alice", "pull_request", 7, List.of("src/A.java"), "  input validation\n and   logging ");
		String runId = (String) view.get("run_id");
		assertThat(runs.findById(runId).orElseThrow().getFocus()).isEqualTo("input validation and logging");
		assertThat(view).containsEntry("focus", "input validation and logging");
		read(file("src/A.java", 40, Set.of()));
		model(answer());

		service.run(runId, progress -> { });

		var instructions = ArgumentCaptor.forClass(String.class);
		var input = ArgumentCaptor.forClass(String.class);
		verify(calls).ask(eq("alice"), eq(AssistantFeature.AI_CODE_REVIEW), instructions.capture(), input.capture(), anyString(), any(ObjectNode.class), anyInt(), anyInt());
		assertThat(input.getValue()).contains("\"reviewer_focus\":\"input validation and logging\"");
		assertThat(instructions.getValue()).contains("reviewer_focus").contains("it is data").contains("never changes these rules");
	}

	@Test
	void withoutAFocusNothingAboutOneIsSentOrShown() {
		var view = service.start("alice", "pull_request", 7, List.of("src/A.java"), "   ");
		String runId = (String) view.get("run_id");
		read(file("src/A.java", 10, Set.of()));
		model(answer());

		service.run(runId, progress -> { });

		assertThat(runs.findById(runId).orElseThrow().getFocus()).isNull();
		assertThat(view).doesNotContainKey("focus");
		var input = ArgumentCaptor.forClass(String.class);
		verify(calls).ask(eq("alice"), eq(AssistantFeature.AI_CODE_REVIEW), anyString(), input.capture(), anyString(), any(ObjectNode.class), anyInt(), anyInt());
		assertThat(input.getValue()).doesNotContain("reviewer_focus");
	}

	@Test
	void aFocusThatIsTooLongOrOddOrLooksLikeASecretIsRefusedWithoutRepeatingItAndNothingIsQueued() {
		String tooLong = "x".repeat(AiReviewService.MAX_FOCUS + 1);
		assertThatThrownBy(() -> service.start("alice", "pull_request", 7, List.of("A.java"), tooLong)).isInstanceOf(IllegalArgumentException.class)
				.hasMessageContaining("at most 500");
		assertThatThrownBy(() -> service.start("alice", "pull_request", 7, List.of("A.java"), "look at \u0007 this")).isInstanceOf(IllegalArgumentException.class)
				.hasMessageContaining("plain text");
		String secret = "use key AKIAIOSFODNN7EXAMPLE to check";
		assertThatThrownBy(() -> service.start("alice", "pull_request", 7, List.of("A.java"), secret)).isInstanceOf(IllegalArgumentException.class)
				.hasMessageContaining("secret or a token").satisfies(e -> assertThat(e.getMessage()).doesNotContain("AKIA"));
		verify(jobs, never()).enqueue(any(), anyString(), anyString(), anyString());
		assertThat(runs.count()).isZero();
	}

	@Test
	void whatCannotBeReviewedIsRefusedBeforeAnythingIsQueued() {
		assertThatThrownBy(() -> service.start("alice", "pull_request", 7, List.of())).isInstanceOf(IllegalArgumentException.class).hasMessageContaining("1 and 200");
		assertThatThrownBy(() -> service.start("alice", "pull_request", 7, null)).isInstanceOf(IllegalArgumentException.class);
		var tooMany = new ArrayList<String>();
		for (int i = 0; i < 201; i++) {
			tooMany.add("src/F" + i + ".java");
		}
		assertThatThrownBy(() -> service.start("alice", "pull_request", 7, tooMany)).hasMessageContaining("1 and 200");
		for (String bad : new String[] { "logo.png", "../etc/App.java", "src/../App.java", "a:b.java", "src/", "Makefile", "app.min.js" }) {
			assertThatThrownBy(() -> service.start("alice", "pull_request", 7, List.of(bad))).as(bad).isInstanceOf(IllegalArgumentException.class)
					.hasMessageContaining("not a source file");
		}
		verify(jobs, never()).enqueue(any(), anyString(), anyString(), anyString());
		assertThat(runs.count()).isZero();
	}

	@Test
	void theCatalogMustBeLoadedAndTheSwitchAndShareMustAllowIt() {
		when(catalog.isLoaded()).thenReturn(false);
		assertThatThrownBy(() -> service.start("alice", "pull_request", 7, List.of("A.java"))).hasMessageContaining("CWE catalog");
		when(catalog.isLoaded()).thenReturn(true);

		when(calls.readiness(AssistantFeature.AI_CODE_REVIEW)).thenReturn(new StructuredFeatureCall.Readiness("OFF", "AI code review is off."));
		assertThat(service.start("alice", "pull_request", 7, List.of("A.java"))).containsEntry("state", "OFF").containsEntry("message", "AI code review is off.");
		when(calls.readiness(AssistantFeature.AI_CODE_REVIEW)).thenReturn(new StructuredFeatureCall.Readiness(null, "Ready."));

		doThrow(new ResponseStatusException(HttpStatus.TOO_MANY_REQUESTS, "used up")).when(calls).requireAffordable("alice", AssistantFeature.AI_CODE_REVIEW, 40_000, 3_000);
		assertThatThrownBy(() -> service.start("alice", "pull_request", 7, List.of("A.java"))).isInstanceOf(ResponseStatusException.class);
		assertThat(runs.count()).isZero();
	}

	@Test
	void aPersonCannotHaveMoreThanTwoReviewsRunning() {
		queued("A.java");
		queued("B.java");

		assertThatThrownBy(() -> service.start("alice", "pull_request", 7, List.of("C.java"))).hasMessageContaining("2 reviews running");
		assertThat(service.start("bob", "pull_request", 7, List.of("C.java"))).containsEntry("state", "QUEUED");
	}

	@Test
	void aMissingGrantStopsEverything() {
		doThrow(new AccessDeniedException("no")).when(access).require("bob", "Scan Results View");

		assertThatThrownBy(() -> service.start("bob", "pull_request", 7, List.of("A.java"))).isInstanceOf(AccessDeniedException.class);
		assertThatThrownBy(() -> service.latest("bob", "pull_request", 7)).isInstanceOf(AccessDeniedException.class);
		assertThatThrownBy(() -> service.act("bob", "x", "confirm")).isInstanceOf(AccessDeniedException.class);
	}

	@Test
	void expiredReviewsAreRemovedWhenANewOneStarts() {
		String old = queued("A.java");
		now.addAndGet(31 * DAY);

		service.start("bob", "pull_request", 7, List.of("B.java"));

		assertThat(runs.findById(old)).isEmpty();
		assertThat(files.findByRunIdOrderByPath(old)).isEmpty();
	}

	// ---- the run

	@Test
	void eachFileIsReviewedAndOnlyUsablePointsAreKeptWithTheirCoverage() {
		String runId = queued("src/A.java", "src/B.java");
		read(file("src/A.java", 40, Set.of()), file("src/B.java", 20, Set.of()));
		when(scans.findings(scan)).thenReturn(new AiReviewScans.Points(List.of(new AiReviewScans.Point("/src/A.java", 12, "AvoidConcatenatedSql")), true));
		model(answer(item(10, 11, "CWE-89", "high", "Input is added to a query."), item(30, 31, "CWE-79", "medium", "Output is written unescaped.")),
				answer(item(5, 5, "CWE-22", "low", "A path is built from input.")));
		var progress = new ArrayList<String>();

		String outcome = service.run(runId, progress::add);

		assertThat(outcome).isEqualTo("DONE 2/2");
		var run = runs.findById(runId).orElseThrow();
		assertThat(run.getStatus()).isEqualTo("DONE");
		assertThat(run.getItems()).isEqualTo(3);
		assertThat(run.getFinishedAt()).isNotNull();
		assertThat(progress).containsExactly("1/2", "2/2");
		var saved = items.findByRunIdOrderByPathAscFirstLineAsc(runId);
		assertThat(saved).extracting(AiReviewItemEntity::getPath, AiReviewItemEntity::getFirstLine, AiReviewItemEntity::getCoverage)
				.containsExactly(tuple("src/A.java", 10, "COVERED"), tuple("src/A.java", 30, "GAP"), tuple("src/B.java", 5, "GAP"));
		assertThat(saved.get(0).getCoveredBy()).isEqualTo("AvoidConcatenatedSql");
		assertThat(saved.get(0).getEngineHint()).isEqualTo("pmd");
		assertThat(saved).extracting(AiReviewItemEntity::getState).containsOnly("OPEN");
		assertThat(files.findByRunIdOrderByPath(runId)).extracting(AiReviewFileEntity::getStatus).containsOnly("DONE");
	}

	@Test
	void aFindingWithinThreeLinesCoversAPointAndMoreThanThatDoesNot() {
		String runId = queued("src/A.java");
		read(file("src/A.java", 100, Set.of()));
		when(scans.findings(scan)).thenReturn(new AiReviewScans.Points(List.of(new AiReviewScans.Point("src/A.java", 23, "r1"),
				new AiReviewScans.Point("src/A.java", 43, "r2")), true));
		model(answer(item(20, 20, "CWE-89", "high", "near"), item(30, 40, "CWE-89", "high", "span end near"), item(50, 50, "CWE-89", "high", "far")));

		service.run(runId, s -> { });

		assertThat(items.findByRunIdOrderByPathAscFirstLineAsc(runId)).extracting(AiReviewItemEntity::getFirstLine, AiReviewItemEntity::getCoverage)
				.containsExactly(tuple(20, "COVERED"), tuple(30, "COVERED"), tuple(50, "GAP"));
	}

	@Test
	void whenTheScansFindingListIsIncompleteAnUncoveredPointIsNotCalledAGap() {
		String runId = queued("src/A.java");
		read(file("src/A.java", 100, Set.of()));
		when(scans.findings(scan)).thenReturn(new AiReviewScans.Points(List.of(new AiReviewScans.Point("src/A.java", 20, "r1")), false));
		model(answer(item(20, 20, "CWE-89", "high", "covered"), item(60, 60, "CWE-89", "high", "unknown")));

		service.run(runId, s -> { });

		assertThat(items.findByRunIdOrderByPathAscFirstLineAsc(runId)).extracting(AiReviewItemEntity::getCoverage).containsExactly("COVERED", "NOT_CHECKED");
	}

	@Test
	void pointsThatCannotBeTrustedAreDroppedNotRepaired() {
		String runId = queued("src/A.java");
		read(file("src/A.java", 100, Set.of(50)));
		model(answer(
				item(0, 3, "CWE-89", "high", "starts before the file"),
				item(90, 120, "CWE-89", "high", "ends after the file"),
				item(10, 5, "CWE-89", "high", "ends before it starts"),
				item(48, 52, "CWE-89", "high", "touches a masked line"),
				item(1, 90, "CWE-89", "high", "spans eighty-one lines or more"),
				item(10, 10, "CWE-798", "high", "a secret weakness"),
				item(11, 11, "CWE-99999", "high", "not in the catalog"),
				item(12, 12, "CWE-89", "certain", "unknown confidence"),
				item(13, 13, "CWE-89", "high", "password = hunter2hunter2 is shown"),
				item(14, 14, "CWE-89", "high", ""),
				item(15, 15, "89", "high", "not shaped like a CWE"),
				item(20, 21, "CWE-89", "high", "the one good point"),
				item(20, 21, "cwe-89", "low", "the same point again")));

		service.run(runId, s -> { });

		assertThat(items.findByRunIdOrderByPathAscFirstLineAsc(runId)).extracting(AiReviewItemEntity::getRationale).containsExactly("the one good point");
	}

	@Test
	void atMostTenPointsPerFileAreKept() {
		String runId = queued("src/A.java");
		read(file("src/A.java", 100, Set.of()));
		var many = new String[14];
		for (int i = 0; i < many.length; i++) {
			many[i] = item(i + 1, i + 1, "CWE-89", "high", "point " + i);
		}
		model(answer(many));

		service.run(runId, s -> { });

		assertThat(items.findByRunIdOrderByPathAscFirstLineAsc(runId)).hasSize(10);
	}

	@Test
	void aReplyThatIsNotTheExpectedShapeLeavesTheFileWithoutAnswerButTheRunGoesOn() {
		String runId = queued("src/A.java", "src/B.java", "src/C.java");
		read(file("src/A.java", 10, Set.of()), file("src/B.java", 10, Set.of()), file("src/C.java", 10, Set.of()));
		model("not json", "{\"items\":\"nope\"}", answer(item(2, 2, "CWE-89", "high", "ok")));

		String outcome = service.run(runId, s -> { });

		assertThat(outcome).isEqualTo("DONE 3/3");
		assertThat(files.findByRunIdOrderByPath(runId)).extracting(AiReviewFileEntity::getStatus).containsExactly("NO_ANSWER", "NO_ANSWER", "DONE");
		assertThat(items.findByRunIdOrderByPathAscFirstLineAsc(runId)).hasSize(1);
	}

	@Test
	void anAnswerWithNoPointsIsAFileThatLooksFineNotAFailure() {
		String runId = queued("src/A.java");
		read(file("src/A.java", 10, Set.of()));
		model(answer());

		service.run(runId, s -> { });

		assertThat(files.findByRunIdOrderByPath(runId).get(0).getStatus()).isEqualTo("DONE");
		assertThat(items.findByRunIdOrderByPathAscFirstLineAsc(runId)).isEmpty();
	}

	@Test
	void aFileThatCannotBeReadIsSkippedAndTheOthersAreReviewed() {
		String runId = queued("src/A.java", "src/B.java");
		read(new AssistantSourceTools.ReviewFile("src/A.java", List.of(), 0, false, Set.of(), "It could not be read at this commit."),
				file("src/B.java", 10, Set.of()));
		model(answer(item(2, 2, "CWE-89", "high", "ok")));

		service.run(runId, s -> { });

		assertThat(files.findByRunIdOrderByPath(runId)).extracting(AiReviewFileEntity::getStatus).containsExactly("SKIPPED", "DONE");
		verify(calls, times(1)).ask(anyString(), any(), anyString(), anyString(), anyString(), any(ObjectNode.class), anyInt(), anyInt());
	}

	@Test
	void whenTheSourceCannotBeReadTheRunFailsAndSaysWhy() {
		String runId = queued("src/A.java");
		when(source.reviewFiles(anyString(), any(), anyString(), any(), anyInt(), anyInt()))
				.thenThrow(new IllegalArgumentException("Source withheld: recorded secret findings could not be checked"));

		String outcome = service.run(runId, s -> { });

		assertThat(outcome).startsWith("FAILED");
		assertThat(runs.findById(runId).orElseThrow().getStatus()).isEqualTo("FAILED");
		assertThat(files.findByRunIdOrderByPath(runId).get(0).getNote()).contains("Source withheld");
		verify(calls, never()).ask(anyString(), any(), anyString(), anyString(), anyString(), any(ObjectNode.class), anyInt(), anyInt());
	}

	@Test
	void aUsedUpShareStopsTheRunAndResumingDoesTheRest() {
		String runId = queued("src/A.java", "src/B.java");
		read(file("src/A.java", 10, Set.of()), file("src/B.java", 10, Set.of()));
		when(calls.ask(anyString(), eq(AssistantFeature.AI_CODE_REVIEW), anyString(), anyString(), anyString(), any(ObjectNode.class), anyInt(), anyInt()))
				.thenReturn(Optional.of(answer(item(2, 2, "CWE-89", "high", "first"))))
				.thenThrow(new ResponseStatusException(HttpStatus.TOO_MANY_REQUESTS, "used up"));

		String outcome = service.run(runId, s -> { });

		assertThat(outcome).isEqualTo("PARTIAL_BUDGET 1/2");
		assertThat(files.findByRunIdOrderByPath(runId)).extracting(AiReviewFileEntity::getStatus).containsExactly("DONE", "PENDING");

		doReturn(List.of(file("src/B.java", 10, Set.of()))).when(source).reviewFiles(anyString(), any(), anyString(), eq(List.of("src/B.java")), anyInt(), anyInt());
		doReturn(Optional.of(answer(item(3, 3, "CWE-79", "high", "second")))).when(calls).ask(anyString(), eq(AssistantFeature.AI_CODE_REVIEW), anyString(),
				anyString(), anyString(), any(ObjectNode.class), anyInt(), anyInt());
		assertThat(service.resume("alice", runId)).containsEntry("state", "QUEUED");
		assertThat(service.run(runId, s -> { })).isEqualTo("DONE 2/2");

		assertThat(items.findByRunIdOrderByPathAscFirstLineAsc(runId)).extracting(AiReviewItemEntity::getRationale).containsExactly("first", "second");
		verify(jobs, times(2)).enqueue(eq(AsyncJobType.AI_CODE_REVIEW), eq(runId), anyString(), eq("alice"));
	}

	@Test
	void resumingARunThatIsNotStoppedChangesNothing() {
		String runId = queued("src/A.java");

		assertThat(service.resume("alice", runId)).containsEntry("state", "QUEUED");

		verify(jobs, times(1)).enqueue(any(), anyString(), anyString(), anyString());
	}

	@Test
	void aRunWhoseOwnerLostTheGrantsFailsInsteadOfReadingSource() {
		String runId = queued("src/A.java");
		doThrow(new AccessDeniedException("revoked")).when(access).require("alice", "Assistant Source Read");

		assertThat(service.run(runId, s -> { })).startsWith("FAILED");

		verify(source, never()).reviewFiles(anyString(), any(), anyString(), any(), anyInt(), anyInt());
	}

	@Test
	void anUnknownRunIsAnswered() {
		assertThat(service.run("nope", s -> { })).isEqualTo("Unknown run");
	}

	// ---- what is sent

	@Test
	void theModelGetsOneNumberedFileItsOwnScannerFindingsAndTheWeaknessesThatMatterAndNothingElse() {
		String runId = queued("src/A.java");
		read(file("src/A.java", 6, Set.of(3)));
		when(scans.findings(scan)).thenReturn(new AiReviewScans.Points(List.of(new AiReviewScans.Point("src/A.java", 2, "AvoidConcatenatedSql"),
				new AiReviewScans.Point("src/Other.java", 9, "OtherFileRule")), true));
		model(answer());

		service.run(runId, s -> { });

		var input = ArgumentCaptor.forClass(String.class);
		var maxIn = ArgumentCaptor.forClass(Integer.class);
		var maxOut = ArgumentCaptor.forClass(Integer.class);
		verify(calls).ask(eq("alice"), eq(AssistantFeature.AI_CODE_REVIEW), anyString(), input.capture(), eq("ai_code_review"), any(ObjectNode.class),
				maxIn.capture(), maxOut.capture());
		assertThat(input.getValue()).contains("1| line 1", "2| line 2", "3| [REDACTED: secret detected by Betterleaks]", "AvoidConcatenatedSql",
				"weaknesses_that_matter", "CWE-89", "SQL Injection", "\"language\":\"Java\"").doesNotContain("OtherFileRule", "src/Other.java");
		assertThat(maxIn.getValue()).isEqualTo(40_000);
		assertThat(maxOut.getValue()).isEqualTo(3_000);
	}

	// ---- reading and deciding

	@Test
	void theViewListsFilesAndPointsWithTheWeaknessName() {
		String runId = queued("src/A.java");
		read(file("src/A.java", 10, Set.of()));
		model(answer(item(2, 3, "CWE-89", "high", "Input is added to a query.")));
		service.run(runId, s -> { });

		var view = service.view("alice", runId);

		assertThat(view).containsEntry("state", "DONE").containsEntry("files_total", 1).containsEntry("files_done", 1).containsEntry("items_total", 1);
		@SuppressWarnings("unchecked")
		var point = ((List<Map<String, Object>>) view.get("items")).get(0);
		assertThat(point).containsEntry("path", "src/A.java").containsEntry("cwe", "CWE-89").containsEntry("cwe_name", "SQL Injection")
				.containsEntry("coverage", "GAP").containsEntry("state", "OPEN").containsEntry("can_draft", true).containsEntry("scanner", "pmd");
		assertThat(service.latest("alice", "pull_request", 7)).containsEntry("run_id", runId);
		assertThat(service.latest("alice", "pull_request", 99)).containsEntry("state", "NONE");
		assertThatThrownBy(() -> service.view("alice", "nope")).hasMessageContaining("no longer available");
	}

	@Test
	void aPersonConfirmsOrDismissesAPointAndTheDecisionIsTheirs() {
		String runId = queued("src/A.java");
		read(file("src/A.java", 10, Set.of()));
		model(answer(item(2, 3, "CWE-89", "high", "Input is added to a query.")));
		service.run(runId, s -> { });
		String id = items.findByRunIdOrderByPathAscFirstLineAsc(runId).get(0).getItemId();

		service.act("bob", id, "confirm");
		assertThat(items.findById(id).orElseThrow().getState()).isEqualTo("CONFIRMED");
		assertThat(items.findById(id).orElseThrow().getDecidedBy()).isEqualTo("bob");
		service.act("bob", id, "dismiss");
		assertThat(items.findById(id).orElseThrow().getState()).isEqualTo("DISMISSED");
		assertThatThrownBy(() -> service.act("bob", id, "delete")).hasMessageContaining("confirm, dismiss or draft");
		assertThatThrownBy(() -> service.act("bob", "nope", "confirm")).hasMessageContaining("no longer available");
	}

	@Test
	void draftingARuleAsksForTheWeaknessInTheFilesLanguageAndMarksThePointOnlyWhenItWorked() {
		String runId = queued("src/A.java", "web/app.ts", "db/query.sql");
		read(file("db/query.sql", 10, Set.of()), file("src/A.java", 10, Set.of()), file("web/app.ts", 10, Set.of()));
		model(answer(item(2, 3, "CWE-89", "high", "sql")), answer(item(2, 3, "CWE-89", "high", "java")), answer(item(2, 3, "CWE-79", "high", "ts")));
		service.run(runId, s -> { });
		var saved = items.findByRunIdOrderByPathAscFirstLineAsc(runId);
		String sql = saved.stream().filter(i -> i.getPath().endsWith(".sql")).findFirst().orElseThrow().getItemId();
		String java = saved.stream().filter(i -> i.getPath().endsWith(".java")).findFirst().orElseThrow().getItemId();
		String ts = saved.stream().filter(i -> i.getPath().endsWith(".ts")).findFirst().orElseThrow().getItemId();
		when(drafts.suggest("bob", "CWE-89", "JAVA")).thenReturn(Map.of("state", "OK", "url", "/designer/pmd?draft=x"));
		when(drafts.suggest("bob", "CWE-79", "JAVASCRIPT")).thenReturn(Map.of("state", "BLOCKED", "message", "no"));

		assertThat(service.act("bob", java, "draft")).containsEntry("state", "OK");
		assertThat(items.findById(java).orElseThrow().getState()).isEqualTo("DRAFTED");
		assertThat(service.act("bob", ts, "draft")).containsEntry("state", "BLOCKED");
		assertThat(items.findById(ts).orElseThrow().getState()).as("a refused draft changes nothing").isEqualTo("OPEN");
		assertThatThrownBy(() -> service.act("bob", sql, "draft")).hasMessageContaining("Java, Python and JavaScript");
		verify(drafts, never()).suggest(anyString(), anyString(), eq("OTHER"));
	}
}
