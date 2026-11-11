package com.tracelink.appsec.watchtower.core.assistant.review;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.tuple;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.web.server.ResponseStatusException;

import com.tracelink.appsec.watchtower.core.assistant.AssistantSecretFindings;
import com.tracelink.appsec.watchtower.core.assistant.AssistantSourceTools;
import com.tracelink.appsec.watchtower.core.assistant.assessment.FindingLocator;
import com.tracelink.appsec.watchtower.core.persistence.LedgerRepository;
import com.tracelink.appsec.watchtower.core.scan.code.scm.api.IScmApi;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.PullRequest;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.data.DiffFile;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.entity.PullRequestContainerEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.entity.PullRequestScanEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.entity.RepoScanEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.report.RepoScanReport;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.report.RepoScanReportService;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.repository.RepoScanRepository;
import com.tracelink.appsec.watchtower.core.scan.repository.RepositoryEntity;

/** Where an AI review reads from, which files can be picked, and the scanner findings it is compared with. */
class AiReviewScansTest {
	private static final String COMMIT = "b".repeat(40);
	private LedgerRepository records;
	private RepoScanRepository repoScans;
	private RepoScanReportService reports;
	private FindingLocator locator;
	private AssistantSecretFindings secrets;
	private AssistantSourceTools source;
	private AiReviewScans scans;
	private RepositoryEntity repo;

	@BeforeEach
	void setUp() {
		records = mock(LedgerRepository.class);
		repoScans = mock(RepoScanRepository.class);
		reports = mock(RepoScanReportService.class);
		locator = mock(FindingLocator.class);
		secrets = mock(AssistantSecretFindings.class);
		source = mock(AssistantSourceTools.class);
		repo = mock(RepositoryEntity.class);
		when(repo.getId()).thenReturn(42L);
		when(repo.getRepoName()).thenReturn("payments");
		when(secrets.secretRules()).thenReturn(new AssistantSecretFindings.SecretRules(Set.of(), Set.of("Hard-coded token"), Set.of("betterleaks")));
		scans = new AiReviewScans(records, repoScans, reports, locator, secrets, source);
	}

	// ---- paths

	@Test
	void spellingsOfOnePathAreTheSameFileAndOnlyThat() {
		assertThat(AiReviewScans.normalize("\\src\\A.java")).isEqualTo("src/A.java");
		assertThat(AiReviewScans.normalize("./src/A.java")).isEqualTo("src/A.java");
		assertThat(AiReviewScans.normalize("/src/A.java")).isEqualTo("src/A.java");
		assertThat(AiReviewScans.normalize(null)).isEmpty();
		assertThat(AiReviewScans.samePath("/app/src/A.java", "src/A.java")).isTrue();
		assertThat(AiReviewScans.samePath("src/A.java", "src/A.java")).isTrue();
		assertThat(AiReviewScans.samePath("src/BA.java", "A.java")).as("a name that merely ends the same way").isFalse();
		assertThat(AiReviewScans.samePath("src/A.java", "src/B.java")).isFalse();
		assertThat(AiReviewScans.samePath("", "src/A.java")).isFalse();
	}

	@Test
	void onlyPlainPathsToSourceFilesAreReviewable() {
		for (String ok : new String[] { "src/A.java", "web/app.TS", "a/b/c.py", "./x/y.go", "infra/main.tf", "conf/app.yaml" }) {
			assertThat(AiReviewScans.reviewable(ok)).as(ok).isTrue();
		}
		for (String bad : new String[] { "", "logo.png", "Makefile", "src/", "../a.java", "a/../b.java", "c:/a.java", "a//b.java", "app.min.js",
				"README", "dir.java/file", "a\0.java", "x".repeat(260) + ".java", ".java" }) {
			assertThat(AiReviewScans.reviewable(bad)).as(bad).isFalse();
		}
	}

	// ---- resolving

	@Test
	void aRepositoryScanResolvesToItsRepositoryAndPinnedCommit() {
		var entity = mock(RepoScanEntity.class);
		when(entity.getRepository()).thenReturn(repo);
		when(entity.getCommitHash()).thenReturn(COMMIT);
		when(repoScans.findById(5L)).thenReturn(Optional.of(entity));

		var scan = scans.resolve("repository", 5);

		assertThat(scan.repository()).isSameAs(repo);
		assertThat(scan.commit()).isEqualTo(COMMIT);
		assertThat(scan.pullRequest()).isNull();
	}

	@Test
	void aPullRequestScanResolvesToItsCatalogRepositoryAndTheScannedCommit() {
		var entity = mock(PullRequestScanEntity.class);
		var container = mock(PullRequestContainerEntity.class);
		var pr = new PullRequest("Bitbucket");
		when(entity.getContainer()).thenReturn(container);
		when(entity.getCommitHash()).thenReturn(COMMIT);
		when(container.toPullRequest()).thenReturn(pr);
		when(container.getApiLabel()).thenReturn("Bitbucket");
		when(container.getRepoName()).thenReturn("Payments");
		when(records.find(PullRequestScanEntity.class, 7L)).thenReturn(entity);
		when(locator.catalogRepository("Bitbucket", "Payments")).thenReturn(repo);

		var scan = scans.resolve("pull_request", 7);

		assertThat(scan.repository()).isSameAs(repo);
		assertThat(scan.pullRequest().getCommitHash()).as("the commit that was scanned, not a later push").isEqualTo(COMMIT);
	}

	@Test
	void whatCannotBeReadIsRefusedWithAReason() {
		assertThatThrownBy(() -> scans.resolve("upload", 1)).isInstanceOf(IllegalArgumentException.class).hasMessageContaining("pull request and repository");
		assertThatThrownBy(() -> scans.resolve(null, 1)).isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> scans.resolve("repository", 0)).isInstanceOf(IllegalArgumentException.class);
		when(repoScans.findById(anyLong())).thenReturn(Optional.empty());
		assertThatThrownBy(() -> scans.resolve("repository", 5)).isInstanceOf(ResponseStatusException.class);

		var notCataloged = mock(RepoScanEntity.class);
		when(notCataloged.getCommitHash()).thenReturn(COMMIT);
		when(repoScans.findById(6L)).thenReturn(Optional.of(notCataloged));
		assertThatThrownBy(() -> scans.resolve("repository", 6)).hasMessageContaining("not in Watchtower's catalog");

		var noCommit = mock(RepoScanEntity.class);
		when(noCommit.getRepository()).thenReturn(repo);
		when(noCommit.getCommitHash()).thenReturn("main");
		when(repoScans.findById(8L)).thenReturn(Optional.of(noCommit));
		assertThatThrownBy(() -> scans.resolve("repository", 8)).hasMessageContaining("commit was not recorded");
	}

	// ---- a short recorded commit

	private static final String SHORT_COMMIT = "84fbc87ae343";
	private static final String FULL_COMMIT = "84fbc87ae343c1d0f4a6b7c8d9e0f1a2b3c4d5e6";

	@Test
	void aShortCommitBitbucketRecordedForAPullRequestIsAcceptedWhenTheScanIsResolved() {
		var entity = mock(PullRequestScanEntity.class);
		var container = mock(PullRequestContainerEntity.class);
		when(entity.getContainer()).thenReturn(container);
		when(entity.getCommitHash()).thenReturn(SHORT_COMMIT);
		when(container.toPullRequest()).thenReturn(new PullRequest("Bitbucket"));
		when(container.getApiLabel()).thenReturn("Bitbucket");
		when(container.getRepoName()).thenReturn("payments");
		when(records.find(PullRequestScanEntity.class, 7L)).thenReturn(entity);
		when(locator.catalogRepository("Bitbucket", "payments")).thenReturn(repo);

		assertThat(scans.resolve("pull_request", 7).commit()).isEqualTo(SHORT_COMMIT);
	}

	@Test
	void aShortCommitIsCompletedByTheSourceControlSystemAndAFullOneIsLeftAlone() throws Exception {
		var api = mock(IScmApi.class);
		when(source.target("alice", 42L)).thenReturn(new AssistantSourceTools.Target(repo, api));
		when(api.fullCommit("payments", SHORT_COMMIT)).thenReturn(FULL_COMMIT);
		var shortScan = new AiReviewScans.Scan("pull_request", 7, repo, SHORT_COMMIT, new PullRequest("Bitbucket"));

		var pinned = scans.pinned("alice", shortScan);

		assertThat(pinned.commit()).isEqualTo(FULL_COMMIT);
		assertThat(pinned.pullRequest()).isSameAs(shortScan.pullRequest());
		var fullScan = new AiReviewScans.Scan("repository", 5, repo, COMMIT, null);
		assertThat(scans.pinned("alice", fullScan)).isSameAs(fullScan);
		verify(api, never()).fullCommit("payments", COMMIT);
	}

	@Test
	void ifTheCommitCannotBeCompletedTheReasonIsPlainAndNothingTechnicalIsShown() throws Exception {
		var api = mock(IScmApi.class);
		when(source.target("alice", 42L)).thenReturn(new AssistantSourceTools.Target(repo, api));
		when(api.fullCommit("payments", SHORT_COMMIT)).thenThrow(new java.io.IOException("Pinned SCM input unavailable: HTTP 404"));
		var shortScan = new AiReviewScans.Scan("pull_request", 7, repo, SHORT_COMMIT, new PullRequest("Bitbucket"));

		assertThatThrownBy(() -> scans.pinned("alice", shortScan)).isInstanceOf(IllegalArgumentException.class)
				.hasMessageContaining("could not be completed to a full hash").satisfies(e -> assertThat(e.getMessage()).doesNotContain("HTTP 404"));
	}

	// ---- findings and candidates

	private RepoScanReport report(int total, RepoScanReport.Finding... findings) {
		return new RepoScanReport(RepoScanReport.SCHEMA, 5, "Bitbucket", "payments", "main", COMMIT, "Default", List.of(findings), List.of(), List.of(), total);
	}

	private AiReviewScans.Scan repositoryScan() {
		var entity = mock(RepoScanEntity.class);
		when(repoScans.findById(5L)).thenReturn(Optional.of(entity));
		when(reports.getReport(entity)).thenReturn(Optional.of(report(5,
				new RepoScanReport.Finding("AvoidConcatenatedSql", "HIGH", "src/Dao.java", 12, "m", "f1", true, false),
				new RepoScanReport.Finding("UnescapedOutput", "HIGH", "src/Dao.java", 40, "m", "f2", true, false),
				new RepoScanReport.Finding("Hard-coded token", "HIGH", "src/Dao.java", 3, "m", "f3", true, false),
				new RepoScanReport.Finding("CheckovRule", "LOW", "README.md", 1, "m", "f4", true, false),
				new RepoScanReport.Finding("Anything", "LOW", "src/Util.py", 7, "m", "f5", true, true))));
		return new AiReviewScans.Scan("repository", 5, repo, COMMIT, null);
	}

	@Test
	void secretFindingsAreLeftOutOfTheComparisonByRuleOrByTheSensitiveFlag() {
		var points = scans.findings(repositoryScan());

		assertThat(points.points()).extracting(AiReviewScans.Point::path, AiReviewScans.Point::line, AiReviewScans.Point::rule)
				.containsExactly(tuple("src/Dao.java", 12, "AvoidConcatenatedSql"), tuple("src/Dao.java", 40, "UnescapedOutput"), tuple("README.md", 1, "CheckovRule"));
	}

	@Test
	void theListIsOnlyCompleteWhenTheReportKeptEveryFinding() {
		var entity = mock(RepoScanEntity.class);
		when(repoScans.findById(5L)).thenReturn(Optional.of(entity));
		var scan = new AiReviewScans.Scan("repository", 5, repo, COMMIT, null);
		when(reports.getReport(entity)).thenReturn(Optional.of(report(1, new RepoScanReport.Finding("r", "LOW", "A.java", 1, "m", "f", true, false))));
		assertThat(scans.findings(scan).complete()).isTrue();

		when(reports.getReport(entity)).thenReturn(Optional.of(report(500, new RepoScanReport.Finding("r", "LOW", "A.java", 1, "m", "f", true, false))));
		assertThat(scans.findings(scan).complete()).as("500 found, 1 kept").isFalse();

		when(reports.getReport(entity)).thenReturn(Optional.empty());
		assertThat(scans.findings(scan)).isEqualTo(new AiReviewScans.Points(List.of(), false));
	}

	@Test
	void aRepositoryScanOffersTheFilesWithFindingsMostFirstAndOnlySourceFiles() {
		var candidates = scans.candidates("alice", repositoryScan());

		assertThat(candidates).extracting(AiReviewScans.Candidate::path, AiReviewScans.Candidate::findings, AiReviewScans.Candidate::changed)
				.containsExactly(tuple("src/Dao.java", 2, false));
	}

	private AiReviewScans.Scan repositoryScanWithoutFindings() {
		var entity = mock(RepoScanEntity.class);
		when(repoScans.findById(5L)).thenReturn(Optional.of(entity));
		when(reports.getReport(entity)).thenReturn(Optional.of(report(0)));
		return new AiReviewScans.Scan("repository", 5, repo, COMMIT, null);
	}

	@Test
	void aRepositoryScanWithoutScannerFindingsStillOffersTheSourceFilesOfItsCommit() {
		var scan = repositoryScanWithoutFindings();
		when(source.sourceFiles(anyString(), any(), anyString(), any(), anyInt())).thenReturn(List.of("core/Image.java", "docs/logo.png", "core/Util.py"));

		var candidates = scans.candidates("alice", scan);

		assertThat(candidates).extracting(AiReviewScans.Candidate::path, AiReviewScans.Candidate::findings, AiReviewScans.Candidate::changed)
				.containsExactly(tuple("core/Image.java", 0, false), tuple("core/Util.py", 0, false));
	}

	@Test
	void filesWithFindingsComeBeforeTheRestOfTheCommitsSourceFiles() {
		when(source.sourceFiles(anyString(), any(), anyString(), any(), anyInt())).thenReturn(List.of("a/First.java", "src/Dao.java", "z/Last.java"));

		var candidates = scans.candidates("alice", repositoryScan());

		assertThat(candidates).extracting(AiReviewScans.Candidate::path, AiReviewScans.Candidate::findings)
				.containsExactly(tuple("src/Dao.java", 2), tuple("a/First.java", 0), tuple("z/Last.java", 0));
	}

	@Test
	void ifTheCommitCannotBeListedTheFilesWithFindingsAreStillOffered() {
		when(source.sourceFiles(anyString(), any(), anyString(), any(), anyInt())).thenThrow(new IllegalArgumentException("Pinned source unavailable"));

		var candidates = scans.candidates("alice", repositoryScan());

		assertThat(candidates).extracting(AiReviewScans.Candidate::path).containsExactly("src/Dao.java");
	}

	@Test
	void ifTheCommitCannotBeListedAndNothingHasFindingsThePersonIsToldWhy() {
		var scan = repositoryScanWithoutFindings();
		when(source.sourceFiles(anyString(), any(), anyString(), any(), anyInt())).thenThrow(new IllegalArgumentException("Pinned source unavailable"));

		assertThatThrownBy(() -> scans.candidates("alice", scan)).isInstanceOf(IllegalArgumentException.class).hasMessageContaining("Pinned source");
	}

	@Test
	void aPullRequestOffersItsChangedFilesLiveWithTheirFindingCounts() {
		var pr = new PullRequest("Bitbucket");
		var scan = new AiReviewScans.Scan("pull_request", 7, repo, COMMIT, pr);
		when(records.maps(anyString(), anyInt(), anyInt(), any(Object[].class))).thenReturn(List.of(
				Map.of("file", "/src/Dao.java", "line", 12, "rule", "AvoidConcatenatedSql", "module", "pmd", "rule_id", 1L),
				Map.of("file", "src/Dao.java", "line", 20, "rule", "Hard-coded token", "module", "regex", "rule_id", 2L)));
		var api = mock(IScmApi.class);
		when(api.getChangedFilesForPullRequest(pr)).thenReturn(Map.of("src/Dao.java", mock(DiffFile.class), "src/New.java", mock(DiffFile.class),
				"docs/logo.png", mock(DiffFile.class)));
		when(source.target("alice", 42L)).thenReturn(new AssistantSourceTools.Target(repo, api));

		var candidates = scans.candidates("alice", scan);

		assertThat(candidates).extracting(AiReviewScans.Candidate::path, AiReviewScans.Candidate::findings, AiReviewScans.Candidate::changed)
				.containsExactly(tuple("src/Dao.java", 1, true), tuple("src/New.java", 0, true));
	}
}
