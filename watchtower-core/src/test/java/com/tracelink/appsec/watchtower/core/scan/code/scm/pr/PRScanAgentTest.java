package com.tracelink.appsec.watchtower.core.scan.code.scm.pr;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import org.hamcrest.MatcherAssert;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.BDDMockito;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import com.tracelink.appsec.watchtower.core.alerting.AlertEvent;
import com.tracelink.appsec.watchtower.core.alerting.AlertService;
import com.tracelink.appsec.watchtower.core.alerting.AlertTypeRegistry;
import com.tracelink.appsec.watchtower.core.exception.RateLimitedException;
import com.tracelink.appsec.watchtower.core.exception.ScanInitializationException;
import com.tracelink.appsec.watchtower.core.module.scanner.ICodeScanner;
import com.tracelink.appsec.watchtower.core.mock.MockCustomRuleDto;
import com.tracelink.appsec.watchtower.core.module.scanner.ScanScope;
import com.tracelink.appsec.watchtower.core.rule.RuleDto;
import com.tracelink.appsec.watchtower.core.rule.RulePriority;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetDto;
import com.tracelink.appsec.watchtower.core.scan.code.CodeScanConfig;
import com.tracelink.appsec.watchtower.core.scan.code.report.CodeScanError;
import com.tracelink.appsec.watchtower.core.scan.code.report.CodeScanReport;
import com.tracelink.appsec.watchtower.core.scan.code.report.CodeScanViolation;
import com.tracelink.appsec.watchtower.core.scan.code.scm.api.IScmApi;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.bypass.ActiveBypass;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.bypass.BypassedFinding;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.bypass.PRScanBypassService;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.data.DiffFile;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.entity.PullRequestViolationEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.service.PRScanResultService;
import com.tracelink.appsec.watchtower.core.scan.queue.SqsScanQueueService;

@ExtendWith(MockitoExtension.class)
public class PRScanAgentTest {
	@Test
	public void selectedRemoteAssessmentPersistsLocalResultsWithoutPublishingScmPass() throws Exception {
		var remote = BDDMockito.mock(com.tracelink.appsec.watchtower.core.scan.code.RemoteAssessmentService.class);
		BDDMockito.when(remote.selected(mockRuleset)).thenReturn(true);
		var agent = newAgent().withRemoteAssessments(remote);
		agent.initialize(); agent.report(List.of(new CodeScanReport()));
		BDDMockito.verify(remote).preparePullRequest(BDDMockito.eq(mockPR), BDDMockito.eq(mockRuleset), BDDMockito.anyLong());
		BDDMockito.verify(mockApi, BDDMockito.never()).approvePR(BDDMockito.any());
		BDDMockito.verify(mockApi, BDDMockito.never()).sendComment(BDDMockito.any(), BDDMockito.anyString());
		BDDMockito.verify(resultsService).savePullRequestScan(BDDMockito.eq(mockPR), BDDMockito.anyLong(), BDDMockito.anyList(),
				BDDMockito.anyList(), BDDMockito.anyLong(), BDDMockito.any(), BDDMockito.any());
	}

	@Mock
	private IScmApi mockApi;

	@Mock
	private PullRequest mockPR;

	@Mock
	private ICodeScanner mockScanner;

	@Mock
	private RulesetDto mockRuleset;

	@Mock
	private PRScanResultService resultsService;

	@Mock
	private SqsScanQueueService mockSqsScanQueueService;


	@Test
	public void testSourceClientNull() {
		PRScanAgent scanAgent = new PRScanAgent(mockPR)
				.withScanners(Collections.singleton(mockScanner))
				.withApi(null).withRuleset(mockRuleset)
				.withBenchmarkEnabled(false).withThreads(1);

		try {
			scanAgent.initialize();
			Assertions.fail("Should have thrown an exception");
		} catch (ScanInitializationException e) {
			Assertions.assertTrue(e.getMessage()
					.contains("API must be configured"));
		}
	}

	@Test
	public void testScanResultServiceNull() {
		PRScanAgent scanAgent = new PRScanAgent(mockPR)
				.withScanners(Collections.singleton(mockScanner))
				.withApi(mockApi).withRuleset(mockRuleset)
				.withBenchmarkEnabled(false).withThreads(1);
		try {
			scanAgent.initialize();
			Assertions.fail("Should have thrown an exception");
		} catch (ScanInitializationException e) {
			Assertions.assertTrue(e.getMessage()
					.contains("Results Service must be configured"));
		}
	}

	@Test
	public void testInitializeRecordsSourceSizeWhenMeterRegistryIsSet() throws Exception {
		// IMPROVEMENT_PLAN.md item 6.6: watchtower.scan.source_size_bytes is recorded once
		// the working directory is populated, but only when a registry is configured -
		// PRScanAgentTest builds most of its agents without one, and initialize() must not
		// throw for those.
		io.micrometer.core.instrument.simple.SimpleMeterRegistry registry =
				new io.micrometer.core.instrument.simple.SimpleMeterRegistry();
		PRScanAgent scanAgent = newAgent().withMeterRegistry(registry);

		scanAgent.initialize();

		Assertions.assertEquals(1,
				registry.get("watchtower.scan.source_size_bytes").summary().count());
	}

	@Test
	public void testInitializeDoesNotRetestTheConnection() throws Exception {
		// PRScanningService already proved connectivity by calling updatePRData() on the
		// same endpoint before queuing this agent, so re-testing it here was one wasted
		// Bitbucket call per scan.
		PRScanAgent scanAgent = newAgent();

		scanAgent.initialize();

		BDDMockito.verify(mockApi, BDDMockito.never())
				.testConnectionForPullRequest(BDDMockito.any());
	}

	@Test
	public void testCollectFilesException() throws IOException {
		PRScanAgent scanAgent = new PRScanAgent(mockPR)
				.withScanners(Collections.singleton(mockScanner))
				.withApi(mockApi).withRuleset(mockRuleset)
				.withBenchmarkEnabled(false).withThreads(1)
				.withScanResultService(resultsService);

		// Only the full-download path (item 2.5) calls downloadSourceForPullRequest().
		BDDMockito.when(mockScanner.getRequiredScope()).thenReturn(ScanScope.FULL_SOURCE);
		BDDMockito.doThrow(IOException.class).when(mockApi)
				.downloadSourceForPullRequest(BDDMockito.any(), BDDMockito.any());

		try {
			scanAgent.initialize();
			Assertions.fail("Should have thrown an exception");
		} catch (ScanInitializationException e) {
			MatcherAssert.assertThat(e.getMessage(),
					Matchers.containsString("Could not download source"));
		}
	}

	@Test
	public void testFullSourceCacheHitExtractsCachedZipWithoutDownloading() throws Exception {
		// IMPROVEMENT_PLAN.md item 3.3: a cache hit skips api.downloadSourceForPullRequest()
		// entirely and extracts the cached zip in its place.
		BDDMockito.when(mockScanner.getRequiredScope()).thenReturn(ScanScope.FULL_SOURCE);
		BDDMockito.when(mockPR.getApiLabel()).thenReturn("api1");
		BDDMockito.when(mockPR.getRepoName()).thenReturn("my-repo");
		BDDMockito.when(mockPR.getCommitHash()).thenReturn("abc123");

		Path fixtureZip = Files.createTempFile("fixture-", ".zip");
		try (java.util.zip.ZipOutputStream zos =
				new java.util.zip.ZipOutputStream(Files.newOutputStream(fixtureZip))) {
			zos.putNextEntry(new java.util.zip.ZipEntry("cached-file.txt"));
			zos.write("hello from cache".getBytes(StandardCharsets.UTF_8));
			zos.closeEntry();
		}

		software.amazon.awssdk.services.s3.S3Client mockS3Client =
				BDDMockito.mock(software.amazon.awssdk.services.s3.S3Client.class);
		ArgumentCaptor<software.amazon.awssdk.services.s3.model.GetObjectRequest> getCaptor =
				ArgumentCaptor.forClass(software.amazon.awssdk.services.s3.model.GetObjectRequest.class);
		BDDMockito.when(mockS3Client.getObject(getCaptor.capture(), BDDMockito.any(Path.class)))
				.thenAnswer(invocation -> {
					Path target = invocation.getArgument(1);
					Files.copy(fixtureZip, target, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
					return software.amazon.awssdk.services.s3.model.GetObjectResponse.builder().build();
				});
		com.tracelink.appsec.watchtower.core.scan.storage.S3Service s3Service =
				new com.tracelink.appsec.watchtower.core.scan.storage.S3Service("my-bucket",
						mockS3Client);

		PRScanAgent scanAgent = new PRScanAgent(mockPR)
				.withScanners(Collections.singleton(mockScanner))
				.withApi(mockApi).withRuleset(mockRuleset)
				.withBenchmarkEnabled(false).withThreads(1)
				.withScanResultService(resultsService)
				.withS3Service(s3Service);

		scanAgent.initialize();

		Path extracted = scanAgent.getWorkingDirectory().resolve("cached-file.txt");
		Assertions.assertTrue(Files.exists(extracted));
		Assertions.assertEquals("hello from cache", Files.readString(extracted));
		Assertions.assertEquals("source/api1/my-repo/abc123.zip", getCaptor.getValue().key());
		BDDMockito.verify(mockApi, BDDMockito.never()).downloadSourceForPullRequest(BDDMockito.any(),
				BDDMockito.any());
	}

	@Test
	public void testFullSourceCacheMissDownloadsFromApiThenCachesAsync() throws Exception {
		// IMPROVEMENT_PLAN.md item 3.3: a cache miss falls back to exactly today's
		// download-and-clean path, then caches the result for next time.
		BDDMockito.when(mockScanner.getRequiredScope()).thenReturn(ScanScope.FULL_SOURCE);
		BDDMockito.when(mockPR.getApiLabel()).thenReturn("api1");
		BDDMockito.when(mockPR.getRepoName()).thenReturn("my-repo");
		BDDMockito.when(mockPR.getCommitHash()).thenReturn("abc123");
		BDDMockito.doAnswer(invocation -> {
			Path workDir = invocation.getArgument(1);
			Files.writeString(workDir.resolve("downloaded.txt"), "fresh download");
			return null;
		}).when(mockApi).downloadSourceForPullRequest(BDDMockito.any(), BDDMockito.any());

		software.amazon.awssdk.services.s3.S3Client mockS3Client =
				BDDMockito.mock(software.amazon.awssdk.services.s3.S3Client.class);
		BDDMockito.when(mockS3Client.getObject(
				BDDMockito.any(software.amazon.awssdk.services.s3.model.GetObjectRequest.class),
				BDDMockito.any(Path.class)))
				.thenThrow(software.amazon.awssdk.services.s3.model.NoSuchKeyException.builder()
						.build());
		com.tracelink.appsec.watchtower.core.scan.storage.S3Service s3Service =
				new com.tracelink.appsec.watchtower.core.scan.storage.S3Service("my-bucket",
						mockS3Client);

		PRScanAgent scanAgent = new PRScanAgent(mockPR)
				.withScanners(Collections.singleton(mockScanner))
				.withApi(mockApi).withRuleset(mockRuleset)
				.withBenchmarkEnabled(false).withThreads(1)
				.withScanResultService(resultsService)
				.withS3Service(s3Service);

		scanAgent.initialize();

		BDDMockito.verify(mockApi).downloadSourceForPullRequest(BDDMockito.eq(mockPR),
				BDDMockito.any());
		Assertions.assertTrue(
				Files.exists(scanAgent.getWorkingDirectory().resolve("downloaded.txt")));

		// The upload itself runs off-thread (a cache write must never block report()), so
		// there's no hook to synchronously wait on a fire-and-forget CompletableFuture -
		// poll briefly instead of asserting immediately.
		ArgumentCaptor<software.amazon.awssdk.services.s3.model.PutObjectRequest> putCaptor =
				ArgumentCaptor.forClass(software.amazon.awssdk.services.s3.model.PutObjectRequest.class);
		long deadline = System.currentTimeMillis() + 2000;
		AssertionError lastFailure = null;
		while (System.currentTimeMillis() < deadline) {
			try {
				BDDMockito.verify(mockS3Client).putObject(putCaptor.capture(),
						BDDMockito.any(software.amazon.awssdk.core.sync.RequestBody.class));
				Assertions.assertEquals("source/api1/my-repo/abc123.zip",
						putCaptor.getValue().key());
				return;
			} catch (AssertionError notYet) {
				lastFailure = notYet;
				Thread.sleep(50);
			}
		}
		throw lastFailure;
	}

	@Test
	public void testFullSourceCacheReadFailureFallsBackToDownloadWithoutFailingScan()
			throws Exception {
		// IMPROVEMENT_PLAN.md item 3.3: S3 is a cache, not a hard dependency - any read
		// failure (not just a clean cache miss) must fall back, never fail the scan.
		BDDMockito.when(mockScanner.getRequiredScope()).thenReturn(ScanScope.FULL_SOURCE);
		BDDMockito.when(mockPR.getApiLabel()).thenReturn("api1");
		BDDMockito.when(mockPR.getRepoName()).thenReturn("my-repo");
		BDDMockito.when(mockPR.getCommitHash()).thenReturn("abc123");

		software.amazon.awssdk.services.s3.S3Client mockS3Client =
				BDDMockito.mock(software.amazon.awssdk.services.s3.S3Client.class);
		BDDMockito.when(mockS3Client.getObject(
				BDDMockito.any(software.amazon.awssdk.services.s3.model.GetObjectRequest.class),
				BDDMockito.any(Path.class)))
				.thenThrow(software.amazon.awssdk.services.s3.model.S3Exception.builder()
						.message("S3 is down").build());
		com.tracelink.appsec.watchtower.core.scan.storage.S3Service s3Service =
				new com.tracelink.appsec.watchtower.core.scan.storage.S3Service("my-bucket",
						mockS3Client);

		PRScanAgent scanAgent = new PRScanAgent(mockPR)
				.withScanners(Collections.singleton(mockScanner))
				.withApi(mockApi).withRuleset(mockRuleset)
				.withBenchmarkEnabled(false).withThreads(1)
				.withScanResultService(resultsService)
				.withS3Service(s3Service);

		// Must not throw despite the S3 failure.
		scanAgent.initialize();

		BDDMockito.verify(mockApi).downloadSourceForPullRequest(BDDMockito.eq(mockPR),
				BDDMockito.any());
	}

	@Test
	public void testInitializeSuccess() throws ScanInitializationException {
		PRScanAgent scanAgent = new PRScanAgent(mockPR)
				.withScanners(Collections.singleton(mockScanner))
				.withApi(mockApi).withRuleset(mockRuleset)
				.withBenchmarkEnabled(false).withThreads(1)
				.withScanResultService(resultsService);

		scanAgent.initialize();
	}



	@Test
	public void testCollectUninteresting() throws ScanInitializationException, IOException {
		PRScanAgent scanAgent = new PRScanAgent(mockPR)
				.withScanners(Collections.singleton(mockScanner))
				.withApi(mockApi).withRuleset(mockRuleset)
				.withBenchmarkEnabled(false).withThreads(1)
				.withScanResultService(resultsService);

		// Cleanup only runs on the full-download path (item 2.5) - a CHANGED_FILES-only
		// scan never touches these files at all.
		BDDMockito.when(mockScanner.getRequiredScope()).thenReturn(ScanScope.FULL_SOURCE);

		Path wd = scanAgent.getWorkingDirectory();
		Path uninDir = wd.resolve("test");
		Path uninFile = wd.resolve("foo.jar");
		Files.createDirectory(uninDir);
		Files.createFile(uninFile);

		scanAgent.initialize();
		Assertions.assertFalse(uninDir.toFile().exists());
		Assertions.assertFalse(uninFile.toFile().exists());
	}

	/**
	 * Makes {@link #mockScanner} one the ruleset actually runs: it supports
	 * {@link MockCustomRuleDto} and the ruleset contains one.
	 */
	private void givenRulesetRunsMockScanner() {
		BDDMockito.when(mockScanner.getSupportedRuleClass())
				.thenReturn(List.<Class<? extends RuleDto>>of(MockCustomRuleDto.class));
		BDDMockito.when(mockRuleset.getAllRules()).thenReturn(Set.of(new MockCustomRuleDto()));
	}

	@Test
	public void testFullDownloadKeepsAFolderARunningScannerDoesNotExclude() throws Exception {
		// A secrets scanner must see test/ - fixtures are a common place to commit a real key.
		givenRulesetRunsMockScanner();
		BDDMockito.when(mockScanner.getRequiredScope()).thenReturn(ScanScope.FULL_SOURCE);
		BDDMockito.when(mockScanner.getExcludedFolders()).thenReturn(Set.of("node_modules"));
		PRScanAgent scanAgent = new PRScanAgent(mockPR)
				.withScanners(Collections.singleton(mockScanner))
				.withApi(mockApi).withRuleset(mockRuleset)
				.withBenchmarkEnabled(false).withThreads(1)
				.withScanResultService(resultsService);
		Path wd = scanAgent.getWorkingDirectory();
		Path testDir = Files.createDirectory(wd.resolve("test"));
		Path nodeModulesDir = Files.createDirectory(wd.resolve("node_modules"));

		scanAgent.initialize();

		Assertions.assertTrue(testDir.toFile().exists());
		Assertions.assertFalse(nodeModulesDir.toFile().exists());
	}

	@Test
	public void testFullDownloadExcludesOnlyFoldersEveryRunningScannerExcludes()
			throws Exception {
		givenRulesetRunsMockScanner();
		BDDMockito.when(mockScanner.getRequiredScope()).thenReturn(ScanScope.FULL_SOURCE);
		BDDMockito.when(mockScanner.getExcludedFolders())
				.thenReturn(ICodeScanner.DEFAULT_EXCLUDED_FOLDERS);
		ICodeScanner secretsScanner = BDDMockito.mock(ICodeScanner.class);
		BDDMockito.when(secretsScanner.getSupportedRuleClass())
				.thenReturn(List.<Class<? extends RuleDto>>of(MockCustomRuleDto.class));
		BDDMockito.when(secretsScanner.getExcludedFolders()).thenReturn(Set.of("node_modules"));
		PRScanAgent scanAgent = new PRScanAgent(mockPR)
				.withScanners(List.of(mockScanner, secretsScanner))
				.withApi(mockApi).withRuleset(mockRuleset)
				.withBenchmarkEnabled(false).withThreads(1)
				.withScanResultService(resultsService);
		Path wd = scanAgent.getWorkingDirectory();
		Path testDir = Files.createDirectory(wd.resolve("test"));
		Path nodeModulesDir = Files.createDirectory(wd.resolve("node_modules"));

		scanAgent.initialize();

		Assertions.assertTrue(testDir.toFile().exists());
		Assertions.assertFalse(nodeModulesDir.toFile().exists());
	}

	@Test
	public void testFullDownloadIgnoresExclusionsOfScannersTheRulesetDoesNotRun()
			throws Exception {
		// Every registered scanner is handed to the agent, whether or not the repo's ruleset
		// has rules for it. A registered-but-unused secrets scanner must not widen what every
		// other repo's scan downloads.
		BDDMockito.when(mockScanner.getRequiredScope()).thenReturn(ScanScope.FULL_SOURCE);
		PRScanAgent scanAgent = new PRScanAgent(mockPR)
				.withScanners(Collections.singleton(mockScanner))
				.withApi(mockApi).withRuleset(mockRuleset)
				.withBenchmarkEnabled(false).withThreads(1)
				.withScanResultService(resultsService);
		Path testDir = Files.createDirectory(scanAgent.getWorkingDirectory().resolve("test"));

		scanAgent.initialize();

		Assertions.assertFalse(testDir.toFile().exists());
		BDDMockito.verify(mockScanner, BDDMockito.never()).getExcludedFolders();
	}

	@Test
	public void testScanConfigNamesTheRepositoryBeingScanned() {
		// Repository-scoped settings (e.g. a secrets allowlist entry for one repo) need it.
		BDDMockito.when(mockPR.getRepoName()).thenReturn("payments-service");
		PRScanAgent scanAgent = new PRScanAgent(mockPR)
				.withScanners(Collections.singleton(mockScanner))
				.withApi(mockApi).withRuleset(mockRuleset)
				.withBenchmarkEnabled(false).withThreads(1)
				.withScanResultService(resultsService);

		Assertions.assertEquals("payments-service",
				scanAgent.createScanConfig().getRepositoryName());
	}

	@Test
	public void testSourceCacheKeyIsUnchangedForTheDefaultExclusions() {
		Assertions.assertEquals("source/api1/my-repo/abc123.zip", PRScanAgent.sourceCacheKey(
				"api1", "my-repo", "abc123", ICodeScanner.DEFAULT_EXCLUDED_FOLDERS));
	}

	@Test
	public void testSourceCacheKeyDiffersWhenTheExclusionsDiffer() {
		// The cached zip is the cleaned tree, so a scan that keeps test/ must never extract a
		// zip cached by a scan that deleted it.
		String defaultKey = PRScanAgent.sourceCacheKey("api1", "my-repo", "abc123",
				ICodeScanner.DEFAULT_EXCLUDED_FOLDERS);
		String nodeModulesOnly = PRScanAgent.sourceCacheKey("api1", "my-repo", "abc123",
				Set.of("node_modules"));
		String nothingExcluded =
				PRScanAgent.sourceCacheKey("api1", "my-repo", "abc123", Set.of());

		Assertions.assertNotEquals(defaultKey, nodeModulesOnly);
		Assertions.assertNotEquals(nodeModulesOnly, nothingExcluded);
		MatcherAssert.assertThat(nodeModulesOnly,
				Matchers.allOf(Matchers.startsWith("source/api1/my-repo/abc123-"),
						Matchers.endsWith(".zip")));
	}

	@Test
	public void testSourceCacheKeyIgnoresExclusionOrder() {
		Assertions.assertEquals(
				PRScanAgent.sourceCacheKey("a", "r", "c",
						new java.util.LinkedHashSet<>(List.of("vendor", "node_modules"))),
				PRScanAgent.sourceCacheKey("a", "r", "c",
						new java.util.LinkedHashSet<>(List.of("node_modules", "vendor"))));
	}

	@Test
	public void testManifestFilesScopeFetchesMatchedAndChangedFilesWithoutFullDownload()
			throws Exception {
		// IMPROVEMENT_PLAN.md item 2.5b: MANIFEST_FILES now does a real scope-aware
		// fetch via listFilesAtCommit(), instead of falling back to a full download.
		BDDMockito.when(mockScanner.getRequiredScope()).thenReturn(ScanScope.MANIFEST_FILES);
		BDDMockito.when(mockScanner.getRequiredFilePatterns())
				.thenReturn(Collections.singletonList("**/*.tf"));
		BDDMockito.when(mockApi.listFilesAtCommit(mockPR))
				.thenReturn(Arrays.asList("main.tf", "modules/variables.tf", "README.md"));
		DiffFile readmeDiff = new DiffFile("README.md", "diffid");
		BDDMockito.when(mockApi.getChangedFilesForPullRequest(mockPR))
				.thenReturn(Collections.singletonMap("README.md", readmeDiff));

		PRScanAgent scanAgent = newAgent();
		scanAgent.initialize();

		// README.md is fetched once, via the changed-files path - not double-fetched
		// again for happening to also appear in the directory listing.
		BDDMockito.verify(mockApi).downloadFileAtCommit(mockPR, "README.md",
				scanAgent.getWorkingDirectory());
		BDDMockito.verify(mockApi).downloadFileAtCommit(mockPR, "main.tf",
				scanAgent.getWorkingDirectory());
		BDDMockito.verify(mockApi).downloadFileAtCommit(mockPR, "modules/variables.tf",
				scanAgent.getWorkingDirectory());
		BDDMockito.verify(mockApi, BDDMockito.never())
				.downloadSourceForPullRequest(BDDMockito.any(), BDDMockito.any());
	}

	@Test
	public void testManifestFilesScopeIgnoresNonMatchingFiles() throws Exception {
		BDDMockito.when(mockScanner.getRequiredScope()).thenReturn(ScanScope.MANIFEST_FILES);
		BDDMockito.when(mockScanner.getRequiredFilePatterns())
				.thenReturn(Collections.singletonList("**/*.tf"));
		BDDMockito.when(mockApi.listFilesAtCommit(mockPR))
				.thenReturn(Arrays.asList("main.tf", "README.md", "src/App.java"));

		PRScanAgent scanAgent = newAgent();
		scanAgent.initialize();

		BDDMockito.verify(mockApi).downloadFileAtCommit(mockPR, "main.tf",
				scanAgent.getWorkingDirectory());
		BDDMockito.verify(mockApi, BDDMockito.never()).downloadFileAtCommit(
				BDDMockito.eq(mockPR), BDDMockito.eq("README.md"), BDDMockito.any());
		BDDMockito.verify(mockApi, BDDMockito.never()).downloadFileAtCommit(
				BDDMockito.eq(mockPR), BDDMockito.eq("src/App.java"), BDDMockito.any());
	}

	@Test
	public void testManifestScopeIsNotWidenedWhenNoChangedFileHasTheScannersTypes()
			throws Exception {
		// A pull request only reports findings in changed files, so a scanner that has no changed file
		// of its types has nothing reportable: do not list the repository or fetch its files for it.
		// Lenient: the scanner is filtered out before its scope is read, but these stubs make the
		// test fail (a listing call) if the filter stops working.
		BDDMockito.lenient().when(mockScanner.getRequiredScope()).thenReturn(ScanScope.MANIFEST_FILES);
		BDDMockito.lenient().when(mockScanner.getRequiredFilePatterns())
				.thenReturn(Collections.singletonList("**/*.tf"));
		BDDMockito.when(mockScanner.getFileTypes()).thenReturn(List.of(".tf"));
		BDDMockito.when(mockApi.getChangedFilesForPullRequest(mockPR))
				.thenReturn(Collections.singletonMap("src/App.java", new DiffFile("src/App.java", "d")));

		PRScanAgent scanAgent = newAgent();
		scanAgent.initialize();

		BDDMockito.verify(mockApi, BDDMockito.never()).listFilesAtCommit(BDDMockito.any());
		BDDMockito.verify(mockApi).downloadFileAtCommit(mockPR, "src/App.java",
				scanAgent.getWorkingDirectory());
	}

	@Test
	public void testManifestScopeStillFetchesSiblingsWhenAChangedFileHasTheScannersTypes()
			throws Exception {
		BDDMockito.when(mockScanner.getRequiredScope()).thenReturn(ScanScope.MANIFEST_FILES);
		BDDMockito.when(mockScanner.getRequiredFilePatterns())
				.thenReturn(Collections.singletonList("**/*.tf"));
		BDDMockito.when(mockScanner.getFileTypes()).thenReturn(List.of(".tf"));
		BDDMockito.when(mockApi.listFilesAtCommit(mockPR))
				.thenReturn(Arrays.asList("main.tf", "modules/variables.tf", "README.md"));
		BDDMockito.when(mockApi.getChangedFilesForPullRequest(mockPR))
				.thenReturn(Collections.singletonMap("main.tf", new DiffFile("main.tf", "d")));

		PRScanAgent scanAgent = newAgent();
		scanAgent.initialize();

		BDDMockito.verify(mockApi).downloadFileAtCommit(mockPR, "modules/variables.tf",
				scanAgent.getWorkingDirectory());
	}

	@Test
	public void testScannerRunsOnlyWhenAChangedFileHasItsTypes() throws Exception {
		BDDMockito.when(mockApi.getChangedFilesForPullRequest(mockPR)).thenReturn(
				java.util.Map.of("docs/readme.md", new DiffFile("docs/readme.md", "d"), "infra/Main.TF",
						new DiffFile("infra/Main.TF", "d")));
		PRScanAgent scanAgent = newAgent();
		scanAgent.initialize();

		Assertions.assertTrue(scanAgent.hasFileOfType(List.of(".tf"), null));
		Assertions.assertFalse(scanAgent.hasFileOfType(List.of(".java", ".scala"), null));
	}

	@Test
	public void testUnknownChangedFilesFailOpenSoScannersStillRun() throws Exception {
		BDDMockito.when(mockApi.getChangedFilesForPullRequest(mockPR))
				.thenReturn(Collections.emptyMap());
		PRScanAgent scanAgent = newAgent();
		scanAgent.initialize();

		Assertions.assertTrue(scanAgent.hasFileOfType(List.of(".tf"), null));
	}

	@Test
	public void testManifestFilesScopeFallsBackToFullDownloadWhenListingEmpty()
			throws Exception {
		// Ambiguous by design: an empty listing could mean a genuinely empty repo or a
		// failed API call. Falling back to a full download is always correct.
		BDDMockito.when(mockScanner.getRequiredScope()).thenReturn(ScanScope.MANIFEST_FILES);
		BDDMockito.when(mockApi.listFilesAtCommit(mockPR)).thenReturn(Collections.emptyList());

		PRScanAgent scanAgent = newAgent();
		scanAgent.initialize();

		BDDMockito.verify(mockApi).downloadSourceForPullRequest(BDDMockito.eq(mockPR),
				BDDMockito.any());
		BDDMockito.verify(mockApi, BDDMockito.never()).downloadFileAtCommit(BDDMockito.any(),
				BDDMockito.anyString(), BDDMockito.any());
	}

	@Test
	public void testFetchChangedFilesOverThresholdDownloadsFullSourceAndPrunes()
			throws Exception {
		// CHANGED_FILES scope, but the diff touches more files than the configured
		// threshold - should download the whole repo (S3 unconfigured here, so straight
		// to the SCM) and then delete everything that is not a changed file.
		com.tracelink.appsec.watchtower.core.scan.code.scm.pr.entity.PullRequestSyncSettingsEntity settings =
				new com.tracelink.appsec.watchtower.core.scan.code.scm.pr.entity.PullRequestSyncSettingsEntity();
		settings.setFullSourceFileThreshold(2);
		com.tracelink.appsec.watchtower.core.scan.code.scm.pr.service.PullRequestSyncSettingsService mockPrSettingsService =
				BDDMockito.mock(
						com.tracelink.appsec.watchtower.core.scan.code.scm.pr.service.PullRequestSyncSettingsService.class);
		BDDMockito.when(mockPrSettingsService.getSettings()).thenReturn(settings);

		DiffFile diffA = new DiffFile("a.txt", "diffid");
		DiffFile diffB = new DiffFile("b.txt", "diffid");
		DiffFile diffC = new DiffFile("c.txt", "diffid");
		BDDMockito.when(mockApi.getChangedFilesForPullRequest(mockPR)).thenReturn(
				java.util.Map.of("a.txt", diffA, "b.txt", diffB, "c.txt", diffC));
		BDDMockito.doAnswer(invocation -> {
			Path workDir = invocation.getArgument(1);
			Files.writeString(workDir.resolve("a.txt"), "a");
			Files.writeString(workDir.resolve("b.txt"), "b");
			Files.writeString(workDir.resolve("c.txt"), "c");
			Files.writeString(workDir.resolve("unrelated.txt"), "not in the diff");
			Path subdir = workDir.resolve("subdir");
			Files.createDirectory(subdir);
			Files.writeString(subdir.resolve("extra.txt"), "not in the diff either");
			return null;
		}).when(mockApi).downloadSourceForPullRequest(BDDMockito.any(), BDDMockito.any());

		PRScanAgent scanAgent = newAgent()
				.withPullRequestSyncSettingsService(mockPrSettingsService);
		scanAgent.initialize();

		BDDMockito.verify(mockApi).downloadSourceForPullRequest(BDDMockito.eq(mockPR),
				BDDMockito.any());
		BDDMockito.verify(mockApi, BDDMockito.never()).downloadFileAtCommit(BDDMockito.any(),
				BDDMockito.anyString(), BDDMockito.any());

		Path wd = scanAgent.getWorkingDirectory();
		Assertions.assertTrue(Files.exists(wd.resolve("a.txt")));
		Assertions.assertTrue(Files.exists(wd.resolve("b.txt")));
		Assertions.assertTrue(Files.exists(wd.resolve("c.txt")));
		Assertions.assertFalse(Files.exists(wd.resolve("unrelated.txt")));
		Assertions.assertFalse(Files.exists(wd.resolve("subdir")));
	}

	@Test
	public void testFetchChangedFilesAtThresholdStaysPerFile() throws Exception {
		// Exactly at the threshold (not over it) - still the cheaper per-file path, even
		// with a settings service configured.
		com.tracelink.appsec.watchtower.core.scan.code.scm.pr.entity.PullRequestSyncSettingsEntity settings =
				new com.tracelink.appsec.watchtower.core.scan.code.scm.pr.entity.PullRequestSyncSettingsEntity();
		settings.setFullSourceFileThreshold(2);
		com.tracelink.appsec.watchtower.core.scan.code.scm.pr.service.PullRequestSyncSettingsService mockPrSettingsService =
				BDDMockito.mock(
						com.tracelink.appsec.watchtower.core.scan.code.scm.pr.service.PullRequestSyncSettingsService.class);
		BDDMockito.when(mockPrSettingsService.getSettings()).thenReturn(settings);

		DiffFile diffA = new DiffFile("a.txt", "diffid");
		DiffFile diffB = new DiffFile("b.txt", "diffid");
		BDDMockito.when(mockApi.getChangedFilesForPullRequest(mockPR))
				.thenReturn(java.util.Map.of("a.txt", diffA, "b.txt", diffB));

		PRScanAgent scanAgent = newAgent()
				.withPullRequestSyncSettingsService(mockPrSettingsService);
		scanAgent.initialize();

		BDDMockito.verify(mockApi).downloadFileAtCommit(mockPR, "a.txt",
				scanAgent.getWorkingDirectory());
		BDDMockito.verify(mockApi).downloadFileAtCommit(mockPR, "b.txt",
				scanAgent.getWorkingDirectory());
		BDDMockito.verify(mockApi, BDDMockito.never())
				.downloadSourceForPullRequest(BDDMockito.any(), BDDMockito.any());
	}

	@Test
	public void testSourceSizeBytesCapturedAfterCollectFilesAndPassedToSave()
			throws ScanInitializationException, IOException {
		// IMPROVEMENT_PLAN.md item 6.3: source size must reflect what collectFiles() left
		// on disk (post-cleanup), and must reach savePullRequestScan() unchanged.
		PRScanAgent scanAgent = new PRScanAgent(mockPR)
				.withScanners(Collections.singleton(mockScanner))
				.withApi(mockApi).withRuleset(mockRuleset)
				.withBenchmarkEnabled(false).withThreads(1)
				.withScanResultService(resultsService);

		BDDMockito.when(mockScanner.getRequiredScope()).thenReturn(ScanScope.FULL_SOURCE);

		Path wd = scanAgent.getWorkingDirectory();
		byte[] content = "some source content".getBytes(StandardCharsets.UTF_8);
		Files.write(wd.resolve("test.java"), content);

		scanAgent.initialize();

		CodeScanReport report = BDDMockito.mock(CodeScanReport.class);
		BDDMockito.when(report.getViolations()).thenReturn(Collections.emptyList());
		BDDMockito.when(report.getErrors()).thenReturn(Collections.emptyList());
		scanAgent.report(Collections.singletonList(report));

		ArgumentCaptor<Long> sizeCaptor = ArgumentCaptor.forClass(Long.class);
		BDDMockito.verify(resultsService).savePullRequestScan(BDDMockito.any(),
				BDDMockito.anyLong(), BDDMockito.any(), BDDMockito.any(), sizeCaptor.capture(),
				BDDMockito.any(PRScanTimings.class), BDDMockito.any(com.tracelink.appsec.watchtower.core.scan.ScanExecutionSummary.class));
		Assertions.assertEquals(content.length, sizeCaptor.getValue());
	}

	@Test
	public void testReport() {
		PRScanAgent scanAgent = new PRScanAgent(mockPR)
				.withScanners(Collections.singleton(mockScanner))
				.withApi(mockApi).withRuleset(mockRuleset)
				.withBenchmarkEnabled(false).withThreads(1)
				.withScanResultService(resultsService);

		String fileName = "test.java";
		Path filePath = scanAgent.getWorkingDirectory().resolve(fileName);
		int lineNum = 2;
		String message = "message";
		RulePriority severity = RulePriority.HIGH;
		String violationName = "VIOLATION";

		CodeScanViolation violation = new CodeScanViolation();
		violation.setFileName(filePath.toString());
		violation.setLineNum(lineNum);
		violation.setMessage(message);
		violation.setSeverity(severity);
		violation.setViolationName(violationName);

		String errorMessage = "errorMessage";
		CodeScanError error = new CodeScanError(errorMessage);

		CodeScanReport report = BDDMockito.mock(CodeScanReport.class);
		BDDMockito.when(report.getViolations()).thenReturn(Arrays.asList(violation));
		BDDMockito.when(report.getErrors()).thenReturn(Arrays.asList(error));

		BDDMockito.when(mockRuleset.getBlockingLevel()).thenReturn(severity);

		DiffFile diff = BDDMockito.mock(DiffFile.class);
		BDDMockito.when(diff.hasDiffs()).thenReturn(true);
		// PullRequestViolationEntity's constructor relativizes the file name against the
		// working directory, so the map key here is "test.java", not the absolute path the
		// CodeScanViolation above was built with.
		scanAgent.changedFileDiffs = Collections.singletonMap(fileName, diff);

		List<CodeScanReport> reports = Arrays.asList(report);

		scanAgent.report(reports);

		ArgumentCaptor<String> violationsCaptor = ArgumentCaptor.forClass(String.class);
		BDDMockito.verify(mockApi).sendComment(BDDMockito.any(), violationsCaptor.capture());

		String violationString = violationsCaptor.getValue();
		MatcherAssert.assertThat(violationString, Matchers.containsString(fileName));
		MatcherAssert.assertThat(violationString, Matchers.containsString("Pre-existing"));
		MatcherAssert.assertThat(violationString, Matchers.containsString("**No new issues**"));
	}

	@Test
	public void testReportBlockingAndErrors() {
		PRScanAgent scanAgent = new PRScanAgent(mockPR)
				.withScanners(Collections.singleton(mockScanner))
				.withApi(mockApi).withRuleset(mockRuleset)
				.withBenchmarkEnabled(false).withThreads(1)
				.withScanResultService(resultsService);

		String fileName = "test.java";
		Path filePath = scanAgent.getWorkingDirectory().resolve(fileName);
		int lineNum = 2;
		String message = "message";
		RulePriority severity = RulePriority.HIGH;
		String violationName = "VIOLATION";

		CodeScanViolation violation = new CodeScanViolation();
		violation.setFileName(filePath.toString());
		violation.setLineNum(lineNum);
		violation.setMessage(message);
		violation.setSeverity(severity);
		violation.setViolationName(violationName);

		CodeScanReport report = BDDMockito.mock(CodeScanReport.class);
		BDDMockito.when(report.getViolations()).thenReturn(Arrays.asList(violation));
		BDDMockito.when(report.getErrors()).thenReturn(Collections.emptyList());

		BDDMockito.when(mockRuleset.getBlockingLevel()).thenReturn(severity);

		DiffFile diff = BDDMockito.mock(DiffFile.class);
		BDDMockito.when(diff.hasDiffs()).thenReturn(true);
		BDDMockito.when(diff.isLineChanged(lineNum)).thenReturn(true);
		// See testReport() above: the entity relativizes the file name to "test.java".
		scanAgent.changedFileDiffs = Collections.singletonMap(fileName, diff);

		List<CodeScanReport> reports = Arrays.asList(report);

		scanAgent.report(reports);

		ArgumentCaptor<String> violationsCaptor = ArgumentCaptor.forClass(String.class);
		BDDMockito.verify(mockApi).sendComment(BDDMockito.any(), violationsCaptor.capture());

		String violationString = violationsCaptor.getValue();
		MatcherAssert.assertThat(violationString, Matchers.containsString(fileName));
		MatcherAssert.assertThat(violationString,
				Matchers.containsString("**1 new issue (1 blocking)**"));
		MatcherAssert.assertThat(violationString,
				Matchers.not(Matchers.containsString("Pre-existing")));

	}

	/////
	// MCR (Malicious Code Review) characterization tests.
	//
	// These pin behaviour that is deliberately kept as-is. They exist because item 2.6
	// of IMPROVEMENT_PLAN.md rewrites identifyNewViolations(), and the rewrite proposed
	// there silently dropped the +/-5 line window below while its comment claimed the
	// logic was unchanged. Any change to these assertions should be a conscious product
	// decision, not a side effect of a refactor.
	/////

	private static final String MCR_VIOLATION_NAME = "MCR Match: some rule";
	private static final int VIOLATION_LINE = 20;

	/**
	 * Builds a report holding one violation, at {@link #VIOLATION_LINE} of a file the
	 * pull request touched, where exactly one line of that file was changed.
	 *
	 * @param violationName the name to give the violation
	 * @param changedLine   the only line of the file the diff reports as changed
	 * @param scanAgent     the agent the report will be handed to
	 * @return the reports to hand to {@code report()}
	 */
	private List<CodeScanReport> singleViolationReport(String violationName, int changedLine,
			PRScanAgent scanAgent) {
		CodeScanViolation violation = new CodeScanViolation();
		violation.setFileName(scanAgent.getWorkingDirectory().resolve("test.java").toString());
		violation.setLineNum(VIOLATION_LINE);
		violation.setMessage("message");
		violation.setSeverity(RulePriority.HIGH);
		violation.setViolationName(violationName);

		CodeScanReport report = BDDMockito.mock(CodeScanReport.class);
		BDDMockito.when(report.getViolations()).thenReturn(Arrays.asList(violation));
		BDDMockito.when(report.getErrors()).thenReturn(Collections.emptyList());

		BDDMockito.when(mockRuleset.getBlockingLevel()).thenReturn(RulePriority.HIGH);

		DiffFile diff = BDDMockito.mock(DiffFile.class);
		BDDMockito.when(diff.hasDiffs()).thenReturn(true);
		// An Answer rather than a per-line stub: the production code probes a range of
		// lines, and stubbing one it never reaches would trip strict-stub checking.
		BDDMockito.when(diff.isLineChanged(BDDMockito.anyInt()))
				.thenAnswer(invocation -> invocation.getArgument(0, Integer.class) == changedLine);

		// Item 2.6: identifyNewViolations() now reads changedFileDiffs, fetched once in
		// collectFiles(), instead of calling api.getGitDiffFile() per violated file. These
		// tests call report() directly without going through initialize()/collectFiles(),
		// so the field is populated here instead - same package, so direct assignment
		// rather than a test-only setter. Keyed by "test.java", not the absolute path used
		// above: PullRequestViolationEntity's constructor relativizes the file name against
		// the working directory.
		scanAgent.changedFileDiffs = Collections.singletonMap("test.java", diff);

		return Arrays.asList(report);
	}

	@Test
	public void testHandleScanExceptionRequeuesRateLimitedScanWhenSqsConfigured() {
		// IMPROVEMENT_PLAN.md item 4.7: a scan dequeued from SQS that hits Bitbucket's
		// rate limit is re-enqueued with the delay Bitbucket asked for, instead of
		// being failed outright.
		BDDMockito.when(mockSqsScanQueueService.requeue("receipt-1", 30)).thenReturn(true);

		PRScanAgent scanAgent = newAgent()
				.withSqsReceiptHandle("receipt-1")
				.withSqsScanQueueService(mockSqsScanQueueService);

		scanAgent.handleScanException(new RateLimitedException(30));

		BDDMockito.verify(mockSqsScanQueueService).requeue("receipt-1", 30);
	}

	@Test
	public void testHandleScanExceptionFallsBackWhenNoSqsReceiptHandle() {
		// The webhook/manual-submit/downtime-recovery paths never set a receipt handle,
		// so a RateLimitedException there must fall through to the default handling
		// rather than throwing (e.g. a NullPointerException calling requeue()).
		PRScanAgent scanAgent = newAgent();

		Assertions.assertDoesNotThrow(
				() -> scanAgent.handleScanException(new RateLimitedException(30)));
		BDDMockito.verifyNoInteractions(mockSqsScanQueueService);
	}

	@Test
	public void testHandleScanExceptionFallsBackWhenRequeueFails() {
		// The message's own visibility timeout still redelivers it eventually, even
		// when the explicit requeue call itself fails - this must not throw.
		BDDMockito.when(mockSqsScanQueueService.requeue("receipt-1", 30)).thenReturn(false);

		PRScanAgent scanAgent = newAgent()
				.withSqsReceiptHandle("receipt-1")
				.withSqsScanQueueService(mockSqsScanQueueService);

		Assertions.assertDoesNotThrow(
				() -> scanAgent.handleScanException(new RateLimitedException(30)));
		BDDMockito.verify(mockSqsScanQueueService).requeue("receipt-1", 30);
	}

	@Test
	public void testHandleScanExceptionDoesNotRequeueNonRateLimitedExceptions() {
		PRScanAgent scanAgent = newAgent()
				.withSqsReceiptHandle("receipt-1")
				.withSqsScanQueueService(mockSqsScanQueueService);

		Assertions
				.assertDoesNotThrow(() -> scanAgent.handleScanException(new RuntimeException("boom")));
		BDDMockito.verifyNoInteractions(mockSqsScanQueueService);
	}

	private PRScanAgent newAgent() {
		return new PRScanAgent(mockPR)
				.withScanners(Collections.singleton(mockScanner))
				.withApi(mockApi).withRuleset(mockRuleset)
				.withBenchmarkEnabled(false).withThreads(1)
				.withScanResultService(resultsService);
	}

	@SuppressWarnings("unchecked")
	private List<PullRequestViolationEntity> captureSavedViolations() {
		ArgumentCaptor<List<PullRequestViolationEntity>> captor =
				ArgumentCaptor.forClass(List.class);
		BDDMockito.verify(resultsService).savePullRequestScan(BDDMockito.any(),
				BDDMockito.anyLong(), captor.capture(), BDDMockito.any(), BDDMockito.anyLong(),
				BDDMockito.any(PRScanTimings.class), BDDMockito.any(com.tracelink.appsec.watchtower.core.scan.ScanExecutionSummary.class));
		return captor.getValue();
	}

	@Test
	public void testReportSavesTheOriginalPullRequestWithoutRefetching() throws Exception {
		// The PullRequest was fully populated by updatePRData() at queue entry, so
		// report() must persist that object rather than spending another Bitbucket call
		// re-fetching it.
		PRScanAgent scanAgent = newAgent();

		scanAgent.report(singleViolationReport("VIOLATION", VIOLATION_LINE, scanAgent));

		BDDMockito.verify(resultsService).savePullRequestScan(BDDMockito.eq(mockPR),
				BDDMockito.anyLong(), BDDMockito.any(), BDDMockito.any(), BDDMockito.anyLong(),
				BDDMockito.any(PRScanTimings.class), BDDMockito.any(com.tracelink.appsec.watchtower.core.scan.ScanExecutionSummary.class));
		BDDMockito.verify(mockApi, BDDMockito.never()).updatePRData(BDDMockito.any());
	}

	@Test
	public void testViolationIsDroppedWhenTheDiffCannotBeFetched() {
		// changedFileDiffs has no entry for this file - e.g. getChangedFilesForPullRequest()
		// returned a diff that never mentioned it, or the whole fetch failed and
		// collectFiles() left the field at its default empty map. Either way,
		// identifyNewViolations() must drop the violation rather than throw
		// NullPointerException and fail the whole report step for the scan.
		PRScanAgent scanAgent = newAgent();

		CodeScanViolation violation = new CodeScanViolation();
		violation.setFileName(scanAgent.getWorkingDirectory().resolve("test.java").toString());
		violation.setLineNum(VIOLATION_LINE);
		violation.setMessage("message");
		violation.setSeverity(RulePriority.HIGH);
		violation.setViolationName("VIOLATION");

		CodeScanReport report = BDDMockito.mock(CodeScanReport.class);
		BDDMockito.when(report.getViolations()).thenReturn(Arrays.asList(violation));
		BDDMockito.when(report.getErrors()).thenReturn(Collections.emptyList());

		scanAgent.report(Arrays.asList(report));

		MatcherAssert.assertThat(captureSavedViolations(), Matchers.empty());
	}

	@Test
	public void testMcrViolationOnChangedLineBlocksThePullRequest() {
		PRScanAgent scanAgent = newAgent();

		scanAgent.report(singleViolationReport(MCR_VIOLATION_NAME, VIOLATION_LINE, scanAgent));

		// An MCR match at blocking severity on a changed line declines the PR.
		BDDMockito.verify(mockApi).blockPR(BDDMockito.any());
	}

	@Test
	public void testBlockingViolationRequestsChangesAndDoesNotApprove() {
		PRScanAgent scanAgent = newAgent();

		scanAgent.report(singleViolationReport(MCR_VIOLATION_NAME, VIOLATION_LINE, scanAgent));

		BDDMockito.verify(mockApi).requestChangesPR(mockPR);
		BDDMockito.verify(mockApi, BDDMockito.never()).approvePR(BDDMockito.any());
	}

	@Test
	public void testNoBlockingViolationsApprovesAndDoesNotBlock() {
		PRScanAgent scanAgent = newAgent();

		scanAgent.report(Collections.emptyList());

		BDDMockito.verify(mockApi).approvePR(mockPR);
		BDDMockito.verify(mockApi, BDDMockito.never()).requestChangesPR(BDDMockito.any());
		BDDMockito.verify(mockApi, BDDMockito.never()).blockPR(BDDMockito.any());
	}

	@Test
	public void testMcrViolationIsAbsentFromThePullRequestComment() {
		PRScanAgent scanAgent = newAgent();

		scanAgent.report(singleViolationReport(MCR_VIOLATION_NAME, VIOLATION_LINE, scanAgent));

		ArgumentCaptor<String> commentCaptor = ArgumentCaptor.forClass(String.class);
		BDDMockito.verify(mockApi).sendComment(BDDMockito.any(), commentCaptor.capture());
		String comment = commentCaptor.getValue();

		// MCR detail is surfaced through the MCR dashboard, never the PR comment. The
		// consequence, accepted deliberately, is that the PR blocked by the assertion
		// in the test above is declined while its comment reports nothing at all.
		MatcherAssert.assertThat(comment, Matchers.not(Matchers.containsString("test.java")));
		MatcherAssert.assertThat(comment,
				Matchers.not(Matchers.containsString(MCR_VIOLATION_NAME)));
		// The headline is computed without MCR findings too, so it does not hint at one.
		MatcherAssert.assertThat(comment, Matchers.containsString("✅ No new issues"));
		BDDMockito.verify(mockApi, BDDMockito.never()).sendInlineComment(BDDMockito.any(),
				BDDMockito.any(), BDDMockito.anyInt(), BDDMockito.any());
	}

	@Test
	public void testMcrViolationIsKeptWhenAChangedLineIsWithinFiveLines() {
		PRScanAgent scanAgent = newAgent();

		scanAgent.report(
				singleViolationReport(MCR_VIOLATION_NAME, VIOLATION_LINE + 3, scanAgent));

		MatcherAssert.assertThat(captureSavedViolations(), Matchers.hasSize(1));
	}

	@Test
	public void testMcrViolationIsKeptAtExactlyFiveLinesAway() {
		PRScanAgent scanAgent = newAgent();

		scanAgent.report(
				singleViolationReport(MCR_VIOLATION_NAME, VIOLATION_LINE + 5, scanAgent));

		// Pins the boundary of the +/-5 window.
		MatcherAssert.assertThat(captureSavedViolations(), Matchers.hasSize(1));
	}

	@Test
	public void testMcrViolationIsDroppedWhenTheChangedLineIsSixLinesAway() {
		PRScanAgent scanAgent = newAgent();

		scanAgent.report(
				singleViolationReport(MCR_VIOLATION_NAME, VIOLATION_LINE + 6, scanAgent));

		// Just outside the window, so the match is treated as unrelated to this PR.
		MatcherAssert.assertThat(captureSavedViolations(), Matchers.empty());
	}

	@Test
	public void testNonMcrViolationSurvivesRegardlessOfDistanceToAChangedLine() {
		PRScanAgent scanAgent = newAgent();

		scanAgent.report(singleViolationReport("VIOLATION", VIOLATION_LINE + 6, scanAgent));

		// The +/-5 window applies only to MCR findings. An ordinary violation in a
		// touched file is kept and reported as pre-existing.
		List<PullRequestViolationEntity> saved = captureSavedViolations();
		MatcherAssert.assertThat(saved, Matchers.hasSize(1));
		Assertions.assertFalse(saved.get(0).isNewViolation());
	}

	/////
	// Scan-health: incomplete sensitive scans and failed SCM calls
	/////

	/** A scanner whose simple name gives the display name "Secrets". */
	private static final class SecretsScanner implements ICodeScanner {
		private final CodeScanReport report;
		private final boolean sensitive;

		SecretsScanner(CodeScanReport report, boolean sensitive) {
			this.report = report;
			this.sensitive = sensitive;
		}

		@Override
		public CodeScanReport scan(CodeScanConfig config) {
			return report;
		}

		@Override
		public List<Class<? extends RuleDto>> getSupportedRuleClass() {
			return List.of();
		}

		@Override
		public boolean isSensitive() {
			return sensitive;
		}
	}

	private static CodeScanReport reportWithError() {
		CodeScanReport report = new CodeScanReport();
		report.addError(new CodeScanError("Secrets scan incomplete: timed out"));
		return report;
	}

	private String postedComment() {
		ArgumentCaptor<String> captor = ArgumentCaptor.forClass(String.class);
		BDDMockito.verify(mockApi).sendComment(BDDMockito.any(), captor.capture());
		return captor.getValue();
	}

	private List<AlertEvent> raisedAlerts(AlertService alertService, int times) {
		ArgumentCaptor<AlertEvent> captor = ArgumentCaptor.forClass(AlertEvent.class);
		BDDMockito.verify(alertService, BDDMockito.times(times)).raise(captor.capture());
		return captor.getAllValues();
	}

	@Test
	public void testSensitiveScannerErrorAddsAScanIncompleteNoteAndAlerts() {
		AlertService alertService = BDDMockito.mock(AlertService.class);
		BDDMockito.when(mockApi.sendComment(BDDMockito.any(), BDDMockito.any())).thenReturn(true);
		BDDMockito.when(mockApi.approvePR(BDDMockito.any())).thenReturn(true);
		PRScanAgent scanAgent = newAgent().withAlertService(alertService);
		CodeScanReport report = reportWithError();

		scanAgent.executeScanner(new SecretsScanner(report, true), scanAgent.createScanConfig());
		scanAgent.report(List.of(report));

		String comment = postedComment();
		MatcherAssert.assertThat(comment, Matchers.containsString("Scan incomplete"));
		MatcherAssert.assertThat(comment, Matchers.containsString("Secrets"));
		// The scanner's own error text is not echoed into the pull request.
		MatcherAssert.assertThat(comment, Matchers.not(Matchers.containsString("timed out")));
		Assertions.assertEquals(AlertTypeRegistry.SCANNER_FAILURE,
				raisedAlerts(alertService, 1).get(0).type());
	}

	@Test
	public void testNonSensitiveScannerErrorIsNamedOnThePullRequestButDoesNotAlert() {
		AlertService alertService = BDDMockito.mock(AlertService.class);
		BDDMockito.when(mockApi.sendComment(BDDMockito.any(), BDDMockito.any())).thenReturn(true);
		BDDMockito.when(mockApi.approvePR(BDDMockito.any())).thenReturn(true);
		PRScanAgent scanAgent = newAgent().withAlertService(alertService);
		CodeScanReport report = reportWithError();

		scanAgent.executeScanner(new SecretsScanner(report, false), scanAgent.createScanConfig());
		scanAgent.report(List.of(report));

		// A scanner that did not finish may have missed something: the pull request must not
		// read "No new issues". Only sensitive scanners page someone about it.
		String comment = postedComment();
		MatcherAssert.assertThat(comment, Matchers.containsString("Scan incomplete"));
		MatcherAssert.assertThat(comment, Matchers.not(Matchers.containsString("✅ No new issues")));
		BDDMockito.verify(alertService, BDDMockito.never()).raise(BDDMockito.any());
	}

	@Test
	public void testFailedScmCallsRaiseAReviewActionAlert() {
		AlertService alertService = BDDMockito.mock(AlertService.class);
		BDDMockito.when(mockApi.sendComment(BDDMockito.any(), BDDMockito.any())).thenReturn(false);
		BDDMockito.when(mockApi.approvePR(BDDMockito.any())).thenReturn(false);
		PRScanAgent scanAgent = newAgent().withAlertService(alertService);

		scanAgent.report(Collections.emptyList());

		AlertEvent alert = raisedAlerts(alertService, 1).get(0);
		Assertions.assertEquals(AlertTypeRegistry.SCM_REVIEW_ACTION_FAILED, alert.type());
		Assertions.assertEquals(2, alert.items().size());
	}

	@Test
	public void testSuccessfulScanRaisesNoAlert() {
		AlertService alertService = BDDMockito.mock(AlertService.class);
		BDDMockito.when(mockApi.sendComment(BDDMockito.any(), BDDMockito.any())).thenReturn(true);
		BDDMockito.when(mockApi.approvePR(BDDMockito.any())).thenReturn(true);

		newAgent().withAlertService(alertService).report(Collections.emptyList());

		BDDMockito.verifyNoInteractions(alertService);
	}

	/////
	// PR-level bypass (§4.12): a blocking finding an active bypass covers stops blocking.
	/////

	private PRScanAgent agentWithBypass(BypassedFinding... covered) {
		PRScanBypassService bypassService = BDDMockito.mock(PRScanBypassService.class);
		BDDMockito.when(bypassService.activeFor(BDDMockito.any(), BDDMockito.any(),
				BDDMockito.any())).thenReturn(Optional.of(new ActiveBypass("alice",
						"Hotfix\nfor an outage", 1000L, Set.of(covered))));
		return newAgent().withBypassService(bypassService);
	}

	@Test
	public void testBypassedBlockingFindingApprovesInsteadOfBlocking() {
		PRScanAgent scanAgent = agentWithBypass(new BypassedFinding("VIOLATION", "test.java"));

		scanAgent.report(singleViolationReport("VIOLATION", VIOLATION_LINE, scanAgent));

		BDDMockito.verify(mockApi).approvePR(mockPR);
		BDDMockito.verify(mockApi, BDDMockito.never()).requestChangesPR(BDDMockito.any());
		BDDMockito.verify(mockApi, BDDMockito.never()).blockPR(BDDMockito.any());
	}

	@Test
	public void testNewBlockingFindingInAnotherFileStillBlocksAfterBypass() {
		PRScanAgent scanAgent = agentWithBypass(new BypassedFinding("VIOLATION", "other.java"));

		scanAgent.report(singleViolationReport("VIOLATION", VIOLATION_LINE, scanAgent));

		BDDMockito.verify(mockApi).requestChangesPR(mockPR);
		BDDMockito.verify(mockApi).blockPR(mockPR);
		BDDMockito.verify(mockApi, BDDMockito.never()).approvePR(BDDMockito.any());
	}

	@Test
	public void testNewBlockingFindingOfAnotherRuleStillBlocksAfterBypass() {
		PRScanAgent scanAgent = agentWithBypass(new BypassedFinding("OTHER_RULE", "test.java"));

		scanAgent.report(singleViolationReport("VIOLATION", VIOLATION_LINE, scanAgent));

		BDDMockito.verify(mockApi).requestChangesPR(mockPR);
		BDDMockito.verify(mockApi, BDDMockito.never()).approvePR(BDDMockito.any());
	}

	@Test
	public void testBypassedFindingIsStillSavedAndMarked() {
		PRScanAgent scanAgent = agentWithBypass(new BypassedFinding("VIOLATION", "test.java"));

		scanAgent.report(singleViolationReport("VIOLATION", VIOLATION_LINE, scanAgent));

		List<PullRequestViolationEntity> saved = captureSavedViolations();
		Assertions.assertEquals(1, saved.size());
		Assertions.assertTrue(saved.get(0).isNewViolation());
		Assertions.assertTrue(saved.get(0).isBypassed());
		Assertions.assertFalse(saved.get(0).isBlocking());
	}

	@Test
	public void testCommentNamesTheBypass() {
		PRScanAgent scanAgent = agentWithBypass(new BypassedFinding("VIOLATION", "test.java"));

		scanAgent.report(singleViolationReport("VIOLATION", VIOLATION_LINE, scanAgent));

		String comment = postedComment();
		MatcherAssert.assertThat(comment,
				Matchers.containsString("**Blocking bypassed by alice:** `Hotfix for an outage`."));
		MatcherAssert.assertThat(comment, Matchers.containsString("| ✅ High | VIOLATION |"));
		MatcherAssert.assertThat(comment, Matchers.not(Matchers.containsString("⛔")));
	}

	@Test
	public void testCommentOmitsBypassThatCoversNothing() {
		PRScanAgent scanAgent = agentWithBypass(new BypassedFinding("VIOLATION", "other.java"));

		scanAgent.report(singleViolationReport("VIOLATION", VIOLATION_LINE, scanAgent));

		String comment = postedComment();
		MatcherAssert.assertThat(comment, Matchers.not(Matchers.containsString("bypassed")));
		MatcherAssert.assertThat(comment, Matchers.containsString("⛔ Blocking issues found"));
	}

	/////
	// Inline comments and report link (§4.14)
	/////

	@Test
	public void testNewFindingIsCommentedOnItsLineBeforeTheSummary() {
		BDDMockito.when(mockApi.listComments(mockPR)).thenReturn(List.of());
		BDDMockito.when(mockApi.sendInlineComment(BDDMockito.any(), BDDMockito.any(),
				BDDMockito.anyInt(), BDDMockito.any())).thenReturn(true);
		PRScanAgent scanAgent = newAgent();

		scanAgent.report(singleViolationReport("VIOLATION", VIOLATION_LINE, scanAgent));

		org.mockito.InOrder order = BDDMockito.inOrder(mockApi);
		order.verify(mockApi).sendInlineComment(BDDMockito.eq(mockPR),
				BDDMockito.eq("test.java"), BDDMockito.eq(VIOLATION_LINE),
				BDDMockito.startsWith("⛔ **High · VIOLATION** · blocking"));
		order.verify(mockApi).sendComment(BDDMockito.eq(mockPR), BDDMockito.anyString());
		MatcherAssert.assertThat(postedComment(),
				Matchers.not(Matchers.containsString("could not be commented")));
	}

	@Test
	public void testSummaryLinksTheLatestReportWhenAPublicUrlIsSet() {
		BDDMockito.when(mockPR.getApiLabel()).thenReturn("bb cloud");
		BDDMockito.when(mockPR.getRepoName()).thenReturn("payments");
		BDDMockito.when(mockPR.getPrId()).thenReturn("17");
		PRScanAgent scanAgent = newAgent().withPublicUrl("https://wt.example.invalid/");

		scanAgent.report(Collections.emptyList());

		MatcherAssert.assertThat(postedComment(), Matchers.containsString(
				"[Full report](https://wt.example.invalid/scan/report/latest"
						+ "?apiLabel=bb+cloud&repo=payments&prId=17)"));
	}

	@Test
	public void testSummaryHasNoLinkWithoutAPublicUrl() {
		newAgent().report(Collections.emptyList());

		MatcherAssert.assertThat(postedComment(),
				Matchers.not(Matchers.containsString("Full report")));
	}

	private static com.tracelink.appsec.watchtower.core.scan.code.scm.pr.service.PullRequestSyncSettingsService settingsService(
			com.tracelink.appsec.watchtower.core.scan.code.scm.pr.entity.PullRequestSyncSettingsEntity settings) {
		var service = BDDMockito.mock(
				com.tracelink.appsec.watchtower.core.scan.code.scm.pr.service.PullRequestSyncSettingsService.class);
		BDDMockito.when(service.getSettings()).thenReturn(settings);
		return service;
	}

	// The pull request's one status comment (edited in place as the scan moves). On by default; the PR settings switch it.
	private java.util.List<String> statusComments(org.mockito.ArgumentCaptor<String> captor) {
		return captor.getAllValues().stream().filter(c -> c.contains("Watchtower · scan status")).toList();
	}

	@Test
	public void theStatusCommentIsPostedWhenTheScanStartsAndFinishes() throws Exception {
		var settings = new com.tracelink.appsec.watchtower.core.scan.code.scm.pr.entity.PullRequestSyncSettingsEntity();
		var mockPrSettingsService = settingsService(settings);
		BDDMockito.when(mockApi.sendComment(BDDMockito.any(), BDDMockito.anyString())).thenReturn(true);
		var agent = newAgent().withPullRequestSyncSettingsService(mockPrSettingsService);
		agent.initialize();
		agent.report(List.of(new CodeScanReport()));
		var captor = org.mockito.ArgumentCaptor.forClass(String.class);
		BDDMockito.verify(mockApi, BDDMockito.atLeast(2)).sendComment(BDDMockito.any(), captor.capture());
		var status = statusComments(captor);
		Assertions.assertEquals(2, status.size(), status.toString());
		Assertions.assertTrue(status.get(0).contains("Watchtower — started scanning"));
		Assertions.assertFalse(status.get(0).contains("AWS Security Agent"));
		Assertions.assertTrue(status.get(1).contains("✅ No new issues"), "the finished comment is the scan summary");
	}

	@Test
	public void theStatusCommentIsNotPostedWhenTheSettingIsOff() throws Exception {
		var settings = new com.tracelink.appsec.watchtower.core.scan.code.scm.pr.entity.PullRequestSyncSettingsEntity();
		settings.setStatusCommentsEnabled(false);
		var mockPrSettingsService = settingsService(settings);
		var agent = newAgent().withPullRequestSyncSettingsService(mockPrSettingsService);
		agent.initialize();
		agent.report(List.of(new CodeScanReport()));
		var captor = org.mockito.ArgumentCaptor.forClass(String.class);
		BDDMockito.verify(mockApi, BDDMockito.atLeastOnce()).sendComment(BDDMockito.any(), captor.capture());
		Assertions.assertTrue(statusComments(captor).isEmpty());
	}

	@Test
	public void whenAwsIsSelectedTheStatusCommentSaysItsReviewIsRunning() throws Exception {
		var settings = new com.tracelink.appsec.watchtower.core.scan.code.scm.pr.entity.PullRequestSyncSettingsEntity();
		var mockPrSettingsService = settingsService(settings);
		BDDMockito.when(mockApi.sendComment(BDDMockito.any(), BDDMockito.anyString())).thenReturn(true);
		var remote = BDDMockito.mock(com.tracelink.appsec.watchtower.core.scan.code.RemoteAssessmentService.class);
		BDDMockito.when(remote.selected(mockRuleset)).thenReturn(true);
		var agent = newAgent().withRemoteAssessments(remote).withPullRequestSyncSettingsService(mockPrSettingsService);
		agent.initialize();
		agent.report(List.of(new CodeScanReport()));
		var captor = org.mockito.ArgumentCaptor.forClass(String.class);
		BDDMockito.verify(mockApi, BDDMockito.atLeast(2)).sendComment(BDDMockito.any(), captor.capture());
		var status = statusComments(captor);
		Assertions.assertEquals(2, status.size(), status.toString());
		Assertions.assertTrue(status.get(0).contains("Watchtower — started scanning"));
		Assertions.assertFalse(status.get(0).contains("AWS"), "the first comment only says scanning started");
		Assertions.assertTrue(status.get(1).contains("Watchtower's scanners have finished"));
		Assertions.assertTrue(status.get(1).contains("The AWS Security Agent review is still running"));
		Assertions.assertFalse(status.get(1).contains("No new issues"), "the result waits for AWS");
	}

	@Test
	public void aStatusCommentThatCannotBePostedNeverBreaksTheScan() throws Exception {
		var settings = new com.tracelink.appsec.watchtower.core.scan.code.scm.pr.entity.PullRequestSyncSettingsEntity();
		var mockPrSettingsService = settingsService(settings);
		BDDMockito.when(mockApi.listComments(BDDMockito.any())).thenReturn(null);
		var agent = newAgent().withPullRequestSyncSettingsService(mockPrSettingsService);
		agent.initialize();
		agent.report(List.of(new CodeScanReport()));
		BDDMockito.verify(resultsService).savePullRequestScan(BDDMockito.any(), BDDMockito.anyLong(), BDDMockito.anyList(),
				BDDMockito.anyList(), BDDMockito.anyLong(), BDDMockito.any(), BDDMockito.any());
	}
}
