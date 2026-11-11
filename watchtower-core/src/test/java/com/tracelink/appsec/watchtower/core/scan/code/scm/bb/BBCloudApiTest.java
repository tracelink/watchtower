package com.tracelink.appsec.watchtower.core.scan.code.scm.bb;

import java.io.IOException;
import java.nio.file.Files;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.List;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.hamcrest.MatcherAssert;
import org.hamcrest.Matchers;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.mockito.BDDMockito;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.github.tomakehurst.wiremock.client.WireMock;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import com.github.tomakehurst.wiremock.http.Fault;
import com.github.tomakehurst.wiremock.stubbing.Scenario;
import com.tracelink.appsec.watchtower.core.WireMockExtension;
import com.tracelink.appsec.watchtower.core.exception.RateLimitedException;
import com.tracelink.appsec.watchtower.core.exception.ScanRejectedException;
import com.tracelink.appsec.watchtower.core.logging.CoreLogWatchExtension;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.ApiIntegrationException;
import com.tracelink.appsec.watchtower.core.scan.code.report.CodeScanReport;
import com.tracelink.appsec.watchtower.core.scan.code.scm.api.bb.BBCloudApi;
import com.tracelink.appsec.watchtower.core.scan.code.scm.api.bb.BBCloudIntegrationEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.api.bb.BBCloudRejectOption;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.PullRequest;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.PullRequestComment;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.data.DiffFile;

@ExtendWith(MockitoExtension.class)
public class BBCloudApiTest {

	private static final String HEAD_COMMIT = "1234567890";

	@RegisterExtension
	public WireMockExtension wireMockExtension =
			new WireMockExtension(WireMockConfiguration.wireMockConfig().dynamicPort());

	@Mock
	private PullRequest mockPr;

	@Mock
	private CodeScanReport mockReport;

	@Mock
	private PasswordEncoder mockPasswordEncoder;

	@RegisterExtension
	public CoreLogWatchExtension logWatcher = CoreLogWatchExtension.forClass(BBCloudApi.class);

	private String apiBase;
	private String repoBase;
	private String prBase;
	private String workspaceUrl;
	private String hooksUrl;

	private BBCloudIntegrationEntity entity;

	private String buildRequestUrl(String base, String... paths) {
		StringBuilder sb = new StringBuilder(base);
		for (String elem : paths) {
			sb.append("/").append(elem);
		}
		return sb.toString();
	}

	@BeforeEach
	public void setup() {
		wireMockExtension.resetMappings();
		BDDMockito.when(mockPr.getPrId()).thenReturn("123");
		BDDMockito.when(mockPr.getRepoName()).thenReturn("repo");
		apiBase = wireMockExtension.baseUrl();
		repoBase = buildRequestUrl("", "repositories", "myworkspace", mockPr.getRepoName());
		prBase = buildRequestUrl(repoBase, "pullrequests", mockPr.getPrId());
		workspaceUrl = buildRequestUrl("", "workspace");
		hooksUrl = buildRequestUrl("", "workspaces", "myworkspace", "hooks");
		entity = BDDMockito.mock(BBCloudIntegrationEntity.class);
		// BDDMockito.when(entity.makeApiPRUrl(BDDMockito.anyString(), BDDMockito.anyString()))
		// .thenReturn(apiBase + prBase);
		// BDDMockito.when(entity.makeApiWorkspaceUrl())
		// .thenReturn(apiBase + workspaceUrl);
	}

	/////
	// BB Test Client
	/////
	@Test
	public void testClientConnection() throws ApiIntegrationException, JSONException {
		JSONObject json = new JSONObject();
		json.put("pagelen", 1);
		WireMock.stubFor(WireMock.get(workspaceUrl)
				.willReturn(WireMock.aResponse().withStatus(200)
						.withBody(json.toString())));
		BDDMockito.when(entity.makeApiWorkspaceUrl())
				.thenReturn(apiBase + workspaceUrl);
		BBCloudApi testClient = new BBCloudApi(entity);
		testClient.testClientConnection();
	}

	@Test
	public void testClientConnectionNotOk() {
		WireMock.stubFor(WireMock.get(workspaceUrl)
				.willReturn(WireMock.aResponse().withStatus(401)));
		BDDMockito.when(entity.makeApiWorkspaceUrl())
				.thenReturn(apiBase + workspaceUrl);
		BBCloudApi testClient = new BBCloudApi(entity);
		try {
			testClient.testClientConnection();
			Assertions.fail("Should throw exception");
		} catch (ApiIntegrationException e) {
			MatcherAssert.assertThat(e.getMessage(),
					Matchers.containsString("Client received 401"));
		}
	}

	@Test
	public void testClientConnectionNoAccess() throws JSONException {
		JSONObject json = new JSONObject();
		json.put("pagelen", 0);
		WireMock.stubFor(WireMock.get(workspaceUrl)
				.willReturn(WireMock.aResponse().withStatus(200)
						.withBody(json.toString())));
		BDDMockito.when(entity.makeApiWorkspaceUrl())
				.thenReturn(apiBase + workspaceUrl);
		BBCloudApi testClient = new BBCloudApi(entity);
		try {
			testClient.testClientConnection();
			Assertions.fail("Should throw exception");
		} catch (ApiIntegrationException e) {
			MatcherAssert.assertThat(e.getMessage(),
					Matchers.containsString("access to 0 respositories"));
		}
	}


	/////
	// BB Retry Logic
	/////
	@Test
	public void testConnectionRateLimitTooManyTries() {
		WireMock.stubFor(WireMock.get(buildRequestUrl(prBase))
				.willReturn(WireMock.aResponse().withStatus(429).withHeader("Retry-After", "20")));
		BDDMockito.when(entity.makeApiPRUrl(BDDMockito.anyString(), BDDMockito.anyString()))
				.thenReturn(apiBase + prBase);

		BBCloudApi api = new BBCloudApi(entity);
		Assertions.assertFalse(api.testConnectionForPullRequest(mockPr));
		// 5 retries, plus the first request
		WireMock.verify(5 + 1,
				WireMock.getRequestedFor(WireMock.urlEqualTo(buildRequestUrl(prBase))));
	}

	/////
	// BB Connection Tests
	/////
	@Test
	public void testConnectionOK() throws JSONException {
		JSONObject json = new JSONObject().put("source",
				new JSONObject().put("commit", new JSONObject().put("hash", "1234")));

		BDDMockito.when(entity.makeApiPRUrl(BDDMockito.anyString(), BDDMockito.anyString()))
				.thenReturn(apiBase + prBase);
		WireMock.stubFor(WireMock.get(buildRequestUrl(prBase))
				.willReturn(WireMock.aResponse().withStatus(200).withBody(json.toString())));
		BBCloudApi api = new BBCloudApi(entity);
		Assertions.assertTrue(api.testConnectionForPullRequest(mockPr));
	}

	@Test
	public void testConnectionRateLimit() throws JSONException {
		JSONObject json = new JSONObject().put("source",
				new JSONObject().put("commit", new JSONObject().put("hash", "1234")));

		WireMock.stubFor(WireMock.get(buildRequestUrl(prBase))
				.willReturn(WireMock.aResponse().withStatus(429).withHeader("Retry-After", "20"))
				.inScenario("connRateLimit").whenScenarioStateIs(Scenario.STARTED)
				.willSetStateTo("ok"));

		WireMock.stubFor(WireMock.get(buildRequestUrl(prBase))
				.willReturn(WireMock.aResponse().withStatus(200).withBody(json.toString()))//
				.inScenario("connRateLimit").whenScenarioStateIs("ok"));
		BDDMockito.when(entity.makeApiPRUrl(BDDMockito.anyString(), BDDMockito.anyString()))
				.thenReturn(apiBase + prBase);

		BBCloudApi api = new BBCloudApi(entity);
		Assertions.assertTrue(api.testConnectionForPullRequest(mockPr));
	}

	@Test
	public void testConnectionBad() {
		WireMock.stubFor(WireMock.get(buildRequestUrl(prBase))
				.willReturn(WireMock.aResponse().withStatus(404)));
		BDDMockito.when(entity.makeApiPRUrl(BDDMockito.anyString(), BDDMockito.anyString()))
				.thenReturn(apiBase + prBase);

		BBCloudApi api = new BBCloudApi(entity);
		Assertions.assertFalse(api.testConnectionForPullRequest(mockPr));
		Assertions.assertTrue(logWatcher.getMessages().get(0).contains("testing connection"));
	}

	@Test
	public void testConnectionExcept() {
		WireMock.stubFor(WireMock.get(buildRequestUrl(prBase))
				.willReturn(WireMock.aResponse().withFault(Fault.CONNECTION_RESET_BY_PEER)));
		BDDMockito.when(entity.makeApiPRUrl(BDDMockito.anyString(), BDDMockito.anyString()))
				.thenReturn(apiBase + prBase);

		BBCloudApi api = new BBCloudApi(entity);
		Assertions.assertFalse(api.testConnectionForPullRequest(mockPr));
		Assertions.assertTrue(
				logWatcher.getMessages().get(0)
						.contains("Exception while connecting to Bitbucket"));
	}


	/////
	// Completing the short commit hash Bitbucket gives for a pull request
	/////
	private static final String FULL_COMMIT = "84fbc87ae343c1d0f4a6b7c8d9e0f1a2b3c4d5e6";

	@Test
	public void testFullCommitCompletesTheShortHashBitbucketGivesForAPullRequest() throws Exception {
		BDDMockito.when(entity.makeApiRepoUrl(BDDMockito.anyString())).thenReturn(apiBase + repoBase);
		WireMock.stubFor(WireMock.get(repoBase + "/commit/84fbc87ae343").willReturn(WireMock.aResponse().withStatus(200)
				.withBody(new JSONObject().put("hash", FULL_COMMIT).toString())));

		Assertions.assertEquals(FULL_COMMIT, new BBCloudApi(entity).fullCommit("repo", "84fbc87ae343"));
	}

	@Test
	public void testFullCommitLeavesAFullHashAloneWithoutAskingBitbucket() throws Exception {
		Assertions.assertEquals(FULL_COMMIT, new BBCloudApi(entity).fullCommit("repo", FULL_COMMIT));

		WireMock.verify(0, WireMock.getRequestedFor(WireMock.urlMatching(".*")));
	}

	@Test
	public void testFullCommitRefusesAnAnswerThatIsNotTheCommitAskedFor() throws Exception {
		BDDMockito.when(entity.makeApiRepoUrl(BDDMockito.anyString())).thenReturn(apiBase + repoBase);
		WireMock.stubFor(WireMock.get(repoBase + "/commit/84fbc87ae343").willReturn(WireMock.aResponse().withStatus(200)
				.withBody(new JSONObject().put("hash", "ffffffffffffffffffffffffffffffffffffffff").toString())));

		Assertions.assertThrows(IOException.class, () -> new BBCloudApi(entity).fullCommit("repo", "84fbc87ae343"));
	}

	@Test
	public void testFullCommitFailsWhenBitbucketDoesNotKnowTheCommitOrAnswersBadly() throws Exception {
		BDDMockito.when(entity.makeApiRepoUrl(BDDMockito.anyString())).thenReturn(apiBase + repoBase);
		WireMock.stubFor(WireMock.get(repoBase + "/commit/aaaaaaaaaaaa").willReturn(WireMock.aResponse().withStatus(404)));
		WireMock.stubFor(WireMock.get(repoBase + "/commit/bbbbbbbbbbbb").willReturn(WireMock.aResponse().withStatus(200).withBody("not json")));
		WireMock.stubFor(WireMock.get(repoBase + "/commit/cccccccccccc").willReturn(WireMock.aResponse().withStatus(200)
				.withBody(new JSONObject().put("hash", "short").toString())));
		BBCloudApi api = new BBCloudApi(entity);

		Assertions.assertThrows(IOException.class, () -> api.fullCommit("repo", "aaaaaaaaaaaa"));
		Assertions.assertThrows(IOException.class, () -> api.fullCommit("repo", "bbbbbbbbbbbb"));
		Assertions.assertThrows(IOException.class, () -> api.fullCommit("repo", "cccccccccccc"));
	}

	@Test
	public void testFullCommitRefusesAnythingThatIsNotAHashWithoutAskingBitbucket() throws Exception {
		BBCloudApi api = new BBCloudApi(entity);

		for (String bad : new String[] { null, "", "main", "abc", "84fbc87ae343/../x", "g4fbc87ae343" }) {
			Assertions.assertThrows(IOException.class, () -> api.fullCommit("repo", bad), String.valueOf(bad));
		}
		WireMock.verify(0, WireMock.getRequestedFor(WireMock.urlMatching(".*")));
	}

	@Test
	public void testDownloadSource() throws Exception {
		byte[] zip = IOUtils.toByteArray(BBCloudApi.class
				.getResourceAsStream("/bbzipdownloadfiles/javatest.zip"));
		WireMock.stubFor(WireMock.get(WireMock.urlMatching("/download"))
				.willReturn(WireMock.aResponse().withStatus(200).withBodyFile("foo.zip")
						.withBody(zip)));
		BDDMockito.when(mockPr.getCommitHash()).thenReturn("01233456789");
		BDDMockito.when(entity.makeDownloadLink(BDDMockito.anyString(), BDDMockito.anyString()))
				.thenReturn(buildRequestUrl(wireMockExtension.baseUrl(), "download"));
		BBCloudApi api = new BBCloudApi(entity);
		java.nio.file.Path zipdl = null;
		try {
			zipdl = Files.createTempDirectory(null);
			api.downloadSourceForPullRequest(mockPr, zipdl);
			Assertions.assertTrue(Files.list(zipdl).count() > 0);
			// A successful download must issue exactly one GET. The source zip is the
			// largest object fetched during a scan, so a redundant request here is the
			// most expensive waste in the whole flow.
			WireMock.verify(1, WireMock.getRequestedFor(WireMock.urlMatching("/download")));
		} finally {
			FileUtils.deleteQuietly(zipdl.toFile());
		}
	}

	@Test
	public void testDownloadSourceFail() throws Exception {
		WireMock.stubFor(WireMock.get(WireMock.urlMatching("/download"))
				.willReturn(WireMock.aResponse().withStatus(404)));
		BDDMockito.when(mockPr.getCommitHash()).thenReturn("01233456789");
		BDDMockito.when(entity.makeDownloadLink(BDDMockito.anyString(), BDDMockito.anyString()))
				.thenReturn(buildRequestUrl(wireMockExtension.baseUrl(), "download"));
		BBCloudApi api = new BBCloudApi(entity);
		java.nio.file.Path zipdl = null;
		try {
			zipdl = Files.createTempDirectory(null);
			api.downloadSourceForPullRequest(mockPr, zipdl);
			Assertions.fail("Should throw exception");
		} catch (IOException e) {
			// success case
		} finally {
			FileUtils.deleteQuietly(zipdl.toFile());
		}
	}

	@Test
	public void testDownloadSourceRetriesThenSucceeds() throws Exception {
		byte[] zip = IOUtils.toByteArray(BBCloudApi.class
				.getResourceAsStream("/bbzipdownloadfiles/javatest.zip"));

		WireMock.stubFor(WireMock.get(WireMock.urlMatching("/download"))
				.willReturn(WireMock.aResponse().withStatus(500))
				.inScenario("downloadRetry").whenScenarioStateIs(Scenario.STARTED)
				.willSetStateTo("ok"));

		WireMock.stubFor(WireMock.get(WireMock.urlMatching("/download"))
				.willReturn(WireMock.aResponse().withStatus(200).withBody(zip))
				.inScenario("downloadRetry").whenScenarioStateIs("ok"));

		BDDMockito.when(mockPr.getCommitHash()).thenReturn("01233456789");
		BDDMockito.when(entity.makeDownloadLink(BDDMockito.anyString(), BDDMockito.anyString()))
				.thenReturn(buildRequestUrl(wireMockExtension.baseUrl(), "download"));
		BBCloudApi api = new BBCloudApi(entity);
		java.nio.file.Path zipdl = null;
		try {
			zipdl = Files.createTempDirectory(null);
			api.downloadSourceForPullRequest(mockPr, zipdl);
			// A failed attempt must be retried, so the second attempt is the one that
			// lands: one failure plus one success is two requests, not five.
			WireMock.verify(2, WireMock.getRequestedFor(WireMock.urlMatching("/download")));
			// The retry must produce a usable tree - content left behind by the failed
			// attempt must not corrupt the archive written by the successful one.
			try (java.util.stream.Stream<java.nio.file.Path> tree = Files.walk(zipdl)) {
				Assertions.assertTrue(tree.anyMatch(Files::isRegularFile),
						"Retried download should extract at least one regular file");
			}
		} finally {
			FileUtils.deleteQuietly(zipdl.toFile());
		}
	}

	@Test
	public void testDownloadSourceEmptyArchiveFailsClearly() throws Exception {
		// An archive that extracts to nothing used to reach Optional.get() on an empty
		// stream and throw NoSuchElementException, which says nothing about the cause.
		java.io.ByteArrayOutputStream emptyZip = new java.io.ByteArrayOutputStream();
		new java.util.zip.ZipOutputStream(emptyZip).close();

		WireMock.stubFor(WireMock.get(WireMock.urlMatching("/download"))
				.willReturn(WireMock.aResponse().withStatus(200)
						.withBody(emptyZip.toByteArray())));
		BDDMockito.when(mockPr.getCommitHash()).thenReturn("01233456789");
		BDDMockito.when(entity.makeDownloadLink(BDDMockito.anyString(), BDDMockito.anyString()))
				.thenReturn(buildRequestUrl(wireMockExtension.baseUrl(), "download"));
		BBCloudApi api = new BBCloudApi(entity);
		java.nio.file.Path zipdl = null;
		try {
			zipdl = Files.createTempDirectory(null);
			api.downloadSourceForPullRequest(mockPr, zipdl);
			Assertions.fail("Should throw exception for an archive with no contents");
		} catch (IOException e) {
			// success case - a diagnosable IOException rather than NoSuchElementException
		} finally {
			FileUtils.deleteQuietly(zipdl.toFile());
		}
	}

	@Test
	public void testDownloadSourceExhaustsRetries() throws Exception {
		WireMock.stubFor(WireMock.get(WireMock.urlMatching("/download"))
				.willReturn(WireMock.aResponse().withStatus(500)));
		BDDMockito.when(mockPr.getCommitHash()).thenReturn("01233456789");
		BDDMockito.when(entity.makeDownloadLink(BDDMockito.anyString(), BDDMockito.anyString()))
				.thenReturn(buildRequestUrl(wireMockExtension.baseUrl(), "download"));
		BBCloudApi api = new BBCloudApi(entity);
		java.nio.file.Path zipdl = null;
		try {
			zipdl = Files.createTempDirectory(null);
			api.downloadSourceForPullRequest(mockPr, zipdl);
			Assertions.fail("Should throw exception once the attempt cap is reached");
		} catch (IOException e) {
			MatcherAssert.assertThat(e.getMessage(), Matchers.containsString("500"));
			// Gives up after the cap rather than retrying forever.
			WireMock.verify(5, WireMock.getRequestedFor(WireMock.urlMatching("/download")));
		} finally {
			FileUtils.deleteQuietly(zipdl.toFile());
		}
	}


	/////
	// BB get git diff file tests
	/////
	@Test
	public void testGetDiff() {
		StringBuilder file = new StringBuilder();
		file.append("@@\n");
		file.append("+ some file\n");
		file.append("- lines\n");
		file.append("  withmultiple\n");

		String fileName = "aFile.java";

		WireMock.stubFor(WireMock.get(WireMock.urlMatching(buildRequestUrl(prBase, "diff.*")))
				.willReturn(WireMock.aResponse().withStatus(200).withBody(file.toString())));
		BDDMockito.when(entity.makeApiPRUrl(BDDMockito.anyString(), BDDMockito.anyString()))
				.thenReturn(apiBase + prBase);

		BBCloudApi api = new BBCloudApi(entity);
		DiffFile gitFile = api.getGitDiffFile(mockPr, fileName);
		Assertions.assertEquals(fileName, gitFile.getPath());
		// Only the changed line numbers are needed, so ask Bitbucket for zero lines of
		// surrounding context rather than pulling back the whole file body.
		WireMock.verify(WireMock
				.getRequestedFor(WireMock.urlPathEqualTo(buildRequestUrl(prBase, "diff")))
				.withQueryParam("path", WireMock.equalTo(fileName))
				.withQueryParam("context", WireMock.equalTo("0")));
	}

	@Test
	public void testGetDiffRateLimit() {
		StringBuilder file = new StringBuilder();
		file.append("@@\n");
		file.append("+ some file\n");
		file.append("- lines\n");
		file.append("  withmultiple\n");

		String fileName = "aFile.java";

		WireMock.stubFor(WireMock.get(WireMock.urlMatching(buildRequestUrl(prBase, "diff.*")))
				.willReturn(WireMock.aResponse().withStatus(429).withHeader("Retry-After", "20"))
				.inScenario("getDiffRateLimit").whenScenarioStateIs(Scenario.STARTED)
				.willSetStateTo("ok"));

		WireMock.stubFor(WireMock.get(WireMock.urlMatching(buildRequestUrl(prBase, "diff.*")))
				.willReturn(WireMock.aResponse().withStatus(200).withBody(file.toString()))
				.inScenario("getDiffRateLimit").whenScenarioStateIs("ok"));
		BDDMockito.when(entity.makeApiPRUrl(BDDMockito.anyString(), BDDMockito.anyString()))
				.thenReturn(apiBase + prBase);

		BBCloudApi api = new BBCloudApi(entity);
		DiffFile gitFile = api.getGitDiffFile(mockPr, fileName);
		Assertions.assertEquals(fileName, gitFile.getPath());
	}

	@Test
	public void testGetDiffBad() {
		String fileName = "aFile.java";

		WireMock.stubFor(WireMock.get(WireMock.urlMatching(buildRequestUrl(prBase, "diff.*")))
				.willReturn(WireMock.aResponse().withStatus(404)));
		BDDMockito.when(entity.makeApiPRUrl(BDDMockito.anyString(), BDDMockito.anyString()))
				.thenReturn(apiBase + prBase);

		BBCloudApi api = new BBCloudApi(entity);
		DiffFile gitFile = api.getGitDiffFile(mockPr, fileName);
		Assertions.assertEquals(null, gitFile);
		Assertions.assertTrue(
				logWatcher.getMessages().get(0).contains("while getting git diff file"));
	}

	@Test
	public void testGetDiffExcept() {
		String fileName = "aFile.java";

		WireMock.stubFor(WireMock.get(WireMock.urlMatching(buildRequestUrl(prBase, "diff.*")))
				.willReturn(WireMock.aResponse().withFault(Fault.CONNECTION_RESET_BY_PEER)));
		BDDMockito.when(entity.makeApiPRUrl(BDDMockito.anyString(), BDDMockito.anyString()))
				.thenReturn(apiBase + prBase);
		BBCloudApi api = new BBCloudApi(entity);
		DiffFile gitFile = api.getGitDiffFile(mockPr, fileName);
		Assertions.assertEquals(null, gitFile);
		Assertions.assertTrue(
				logWatcher.getMessages().get(0).contains("Exception while getting git diff file"));
	}

	@Test
	public void testGetDiffTooBig() {
		String fileName = "aFile.java";

		WireMock.stubFor(WireMock.get(WireMock.urlMatching(buildRequestUrl(prBase, "diff.*")))
				.willReturn(WireMock.aResponse().withStatus(555)));

		BDDMockito.when(entity.makeApiPRUrl(BDDMockito.anyString(), BDDMockito.anyString()))
				.thenReturn(apiBase + prBase);

		BBCloudApi api = new BBCloudApi(entity);
		DiffFile gitFile = api.getGitDiffFile(mockPr, fileName);
		Assertions.assertEquals(null, gitFile);
		Assertions.assertTrue(logWatcher.getMessages().get(0).contains("repo timed out"));
	}

	/////
	// BB get file content tests (inline code snippet on the PR report page)
	/////
	@Test
	public void testGetFileContent() {
		String branch = "feature/foo";
		String filePath = "src/main/Foo.java";
		String content = "class Foo {}";
		BDDMockito.when(mockPr.getSourceBranch()).thenReturn(branch);
		String fileUrl = buildRequestUrl(repoBase, "src", branch, filePath);
		BDDMockito.when(entity.makeSourceFileUrl("repo", branch, filePath))
				.thenReturn(apiBase + fileUrl);
		WireMock.stubFor(WireMock.get(fileUrl)
				.willReturn(WireMock.aResponse().withStatus(200).withBody(content)));

		BBCloudApi api = new BBCloudApi(entity);
		String result = api.getFileContent(mockPr, filePath);
		Assertions.assertEquals(content, result);
	}

	@Test
	public void onlyANotFoundMakesARepositoryGone() {
		// An expired credential or an outage once disabled every repository of an integration
		String workspace = buildRequestUrl("", "repositories", "myworkspace");
		BDDMockito.when(entity.makeApiWorkspaceUrl()).thenReturn(apiBase + workspace);
		BBCloudApi api = new BBCloudApi(entity);
		int[][] cases = {{200, 1}, {404, 0}, {401, 1}, {403, 1}, {500, 1}, {503, 1}};
		for (int[] c : cases) {
			WireMock.stubFor(WireMock.get(buildRequestUrl(workspace, "repo-" + c[0]))
					.willReturn(WireMock.aResponse().withStatus(c[0]).withBody("{}")));
			Assertions.assertEquals(c[1] == 1, api.isRepositoryActive("repo-" + c[0]),
					"HTTP " + c[0]);
		}
	}

	@Test
	public void testGetFileContentNotFoundIsGraceful() {
		String branch = "feature/foo";
		String filePath = "deleted/File.java";
		BDDMockito.when(mockPr.getSourceBranch()).thenReturn(branch);
		String fileUrl = buildRequestUrl(repoBase, "src", branch, filePath);
		BDDMockito.when(entity.makeSourceFileUrl("repo", branch, filePath))
				.thenReturn(apiBase + fileUrl);
		WireMock.stubFor(
				WireMock.get(fileUrl).willReturn(WireMock.aResponse().withStatus(404)));

		BBCloudApi api = new BBCloudApi(entity);
		Assertions.assertNull(api.getFileContent(mockPr, filePath));
		// Logged at debug, not error - a missing file is an expected outcome (deleted or
		// renamed since the scan ran), not a failure worth surfacing at error level.
		Assertions.assertTrue(logWatcher.getMessages().isEmpty());
	}

	@Test
	public void testGetFileContentRateLimit() {
		String branch = "feature/foo";
		String filePath = "src/main/Foo.java";
		String content = "class Foo {}";
		BDDMockito.when(mockPr.getSourceBranch()).thenReturn(branch);
		String fileUrl = buildRequestUrl(repoBase, "src", branch, filePath);
		BDDMockito.when(entity.makeSourceFileUrl("repo", branch, filePath))
				.thenReturn(apiBase + fileUrl);

		WireMock.stubFor(WireMock.get(fileUrl)
				.willReturn(WireMock.aResponse().withStatus(429).withHeader("Retry-After", "20"))
				.inScenario("getFileContentRateLimit").whenScenarioStateIs(Scenario.STARTED)
				.willSetStateTo("ok"));
		WireMock.stubFor(WireMock.get(fileUrl)
				.willReturn(WireMock.aResponse().withStatus(200).withBody(content))
				.inScenario("getFileContentRateLimit").whenScenarioStateIs("ok"));

		BBCloudApi api = new BBCloudApi(entity);
		Assertions.assertEquals(content, api.getFileContent(mockPr, filePath));
	}

	@Test
	public void testGetFileContentBad() {
		String branch = "feature/foo";
		String filePath = "src/main/Foo.java";
		BDDMockito.when(mockPr.getSourceBranch()).thenReturn(branch);
		String fileUrl = buildRequestUrl(repoBase, "src", branch, filePath);
		BDDMockito.when(entity.makeSourceFileUrl("repo", branch, filePath))
				.thenReturn(apiBase + fileUrl);
		WireMock.stubFor(
				WireMock.get(fileUrl).willReturn(WireMock.aResponse().withStatus(500)));

		BBCloudApi api = new BBCloudApi(entity);
		Assertions.assertNull(api.getFileContent(mockPr, filePath));
		Assertions.assertTrue(
				logWatcher.getMessages().get(0).contains("while getting file content"));
	}

	@Test
	public void testGetFileContentExcept() {
		String branch = "feature/foo";
		String filePath = "src/main/Foo.java";
		BDDMockito.when(mockPr.getSourceBranch()).thenReturn(branch);
		String fileUrl = buildRequestUrl(repoBase, "src", branch, filePath);
		BDDMockito.when(entity.makeSourceFileUrl("repo", branch, filePath))
				.thenReturn(apiBase + fileUrl);
		WireMock.stubFor(WireMock.get(fileUrl)
				.willReturn(WireMock.aResponse().withFault(Fault.CONNECTION_RESET_BY_PEER)));

		BBCloudApi api = new BBCloudApi(entity);
		Assertions.assertNull(api.getFileContent(mockPr, filePath));
		Assertions.assertTrue(
				logWatcher.getMessages().get(0).contains("Exception while getting file content"));
	}

	/////
	// BB get changed files for pull request tests - IMPROVEMENT_PLAN.md item 2.3
	/////
	@Test
	public void testGetChangedFilesForPullRequest() {
		String diff = "diff --git a/A.java b/A.java\n"
				+ "--- a/A.java\n"
				+ "+++ b/A.java\n"
				+ "@@ -1,1 +1,2 @@\n"
				+ "+addedA\n"
				+ "diff --git a/B.java b/B.java\n"
				+ "--- a/B.java\n"
				+ "+++ b/B.java\n"
				+ "@@ -100,1 +100,2 @@\n"
				+ "+addedB\n";

		WireMock.stubFor(WireMock.get(WireMock.urlMatching(buildRequestUrl(prBase, "diff.*")))
				.willReturn(WireMock.aResponse().withStatus(200).withBody(diff)));
		BDDMockito.when(entity.makeApiPRUrl(BDDMockito.anyString(), BDDMockito.anyString()))
				.thenReturn(apiBase + prBase);

		BBCloudApi api = new BBCloudApi(entity);
		java.util.Map<String, DiffFile> diffs = api.getChangedFilesForPullRequest(mockPr);

		Assertions.assertEquals(2, diffs.size());
		Assertions.assertTrue(diffs.get("A.java").isLineChanged(1));
		Assertions.assertTrue(diffs.get("B.java").isLineChanged(100));
		// No "path" query param, unlike getGitDiffFile(): fetches every file in one call.
		WireMock.verify(WireMock
				.getRequestedFor(WireMock.urlPathEqualTo(buildRequestUrl(prBase, "diff")))
				.withQueryParam("context", WireMock.equalTo("0")));
	}

	@Test
	public void testGetChangedFilesForPullRequestRateLimit() {
		String diff = "diff --git a/A.java b/A.java\n"
				+ "--- a/A.java\n"
				+ "+++ b/A.java\n"
				+ "@@ -1,1 +1,2 @@\n"
				+ "+addedA\n";

		WireMock.stubFor(WireMock.get(WireMock.urlMatching(buildRequestUrl(prBase, "diff.*")))
				.willReturn(WireMock.aResponse().withStatus(429).withHeader("Retry-After", "20"))
				.inScenario("getChangedFilesRateLimit").whenScenarioStateIs(Scenario.STARTED)
				.willSetStateTo("ok"));
		WireMock.stubFor(WireMock.get(WireMock.urlMatching(buildRequestUrl(prBase, "diff.*")))
				.willReturn(WireMock.aResponse().withStatus(200).withBody(diff))
				.inScenario("getChangedFilesRateLimit").whenScenarioStateIs("ok"));
		BDDMockito.when(entity.makeApiPRUrl(BDDMockito.anyString(), BDDMockito.anyString()))
				.thenReturn(apiBase + prBase);

		BBCloudApi api = new BBCloudApi(entity);
		java.util.Map<String, DiffFile> diffs = api.getChangedFilesForPullRequest(mockPr);

		Assertions.assertEquals(1, diffs.size());
		Assertions.assertTrue(diffs.get("A.java").isLineChanged(1));
	}

	@Test
	public void testGetChangedFilesForPullRequestExhaustedRateLimitThrowsRateLimitedException() {
		// IMPROVEMENT_PLAN.md item 4.7: once the bounded blocking retry is exhausted
		// (every request in this test returns 429, unlike the alternating scenario
		// above), a retriable signal is thrown instead of the retry loop giving up
		// silently.
		WireMock.stubFor(WireMock.get(WireMock.urlMatching(buildRequestUrl(prBase, "diff.*")))
				.willReturn(WireMock.aResponse().withStatus(429).withHeader("Retry-After", "20")));
		BDDMockito.when(entity.makeApiPRUrl(BDDMockito.anyString(), BDDMockito.anyString()))
				.thenReturn(apiBase + prBase);

		BBCloudApi api = new BBCloudApi(entity);
		RateLimitedException ex = Assertions.assertThrows(RateLimitedException.class,
				() -> api.getChangedFilesForPullRequest(mockPr));

		Assertions.assertEquals(20, ex.getRetryAfterSeconds());
	}

	@Test
	public void testGetChangedFilesForPullRequestBad() {
		WireMock.stubFor(WireMock.get(WireMock.urlMatching(buildRequestUrl(prBase, "diff.*")))
				.willReturn(WireMock.aResponse().withStatus(404)));
		BDDMockito.when(entity.makeApiPRUrl(BDDMockito.anyString(), BDDMockito.anyString()))
				.thenReturn(apiBase + prBase);

		BBCloudApi api = new BBCloudApi(entity);
		java.util.Map<String, DiffFile> diffs = api.getChangedFilesForPullRequest(mockPr);

		Assertions.assertTrue(diffs.isEmpty());
		Assertions.assertTrue(
				logWatcher.getMessages().get(0).contains("while getting changed files"));
	}

	@Test
	public void testGetChangedFilesForPullRequestExcept() {
		WireMock.stubFor(WireMock.get(WireMock.urlMatching(buildRequestUrl(prBase, "diff.*")))
				.willReturn(WireMock.aResponse().withFault(Fault.CONNECTION_RESET_BY_PEER)));
		BDDMockito.when(entity.makeApiPRUrl(BDDMockito.anyString(), BDDMockito.anyString()))
				.thenReturn(apiBase + prBase);

		BBCloudApi api = new BBCloudApi(entity);
		java.util.Map<String, DiffFile> diffs = api.getChangedFilesForPullRequest(mockPr);

		Assertions.assertTrue(diffs.isEmpty());
		Assertions.assertTrue(logWatcher.getMessages().get(0)
				.contains("Exception while getting changed files"));
	}

	@Test
	public void testGetChangedFilesForPullRequestTooBig() {
		WireMock.stubFor(WireMock.get(WireMock.urlMatching(buildRequestUrl(prBase, "diff.*")))
				.willReturn(WireMock.aResponse().withStatus(555)));
		BDDMockito.when(entity.makeApiPRUrl(BDDMockito.anyString(), BDDMockito.anyString()))
				.thenReturn(apiBase + prBase);

		BBCloudApi api = new BBCloudApi(entity);
		java.util.Map<String, DiffFile> diffs = api.getChangedFilesForPullRequest(mockPr);

		Assertions.assertTrue(diffs.isEmpty());
		Assertions.assertTrue(logWatcher.getMessages().get(0).contains("repo timed out"));
	}

	/////
	// BB download file at commit tests - IMPROVEMENT_PLAN.md item 2.4
	/////
	@Test
	public void testDownloadFileAtCommit() throws IOException {
		String commitHash = "abc123";
		String filePath = "src/main/Foo.java";
		String content = "class Foo {}";
		BDDMockito.when(mockPr.getCommitHash()).thenReturn(commitHash);
		String fileUrl = buildRequestUrl(repoBase, "src", commitHash, filePath);
		BDDMockito.when(entity.makeSourceFileUrl("repo", commitHash, filePath))
				.thenReturn(apiBase + fileUrl);
		WireMock.stubFor(WireMock.get(fileUrl)
				.willReturn(WireMock.aResponse().withStatus(200).withBody(content)));

		java.nio.file.Path targetDir = Files.createTempDirectory("bbtest");
		try {
			BBCloudApi api = new BBCloudApi(entity);
			api.downloadFileAtCommit(mockPr, filePath, targetDir);

			java.nio.file.Path written = targetDir.resolve(filePath);
			Assertions.assertTrue(Files.exists(written));
			Assertions.assertEquals(content, new String(Files.readAllBytes(written)));
		} finally {
			FileUtils.deleteQuietly(targetDir.toFile());
		}
	}

	@Test
	public void testDownloadSourceByRepoAndCommit() throws Exception {
		byte[] zip = IOUtils.toByteArray(BBCloudApi.class
				.getResourceAsStream("/bbzipdownloadfiles/javatest.zip"));
		WireMock.stubFor(WireMock.get(WireMock.urlMatching("/download"))
				.willReturn(WireMock.aResponse().withStatus(200).withBody(zip)));
		BDDMockito.when(entity.makeDownloadLink("other-repo", "01233456789"))
				.thenReturn(buildRequestUrl(wireMockExtension.baseUrl(), "download"));
		java.nio.file.Path target = Files.createTempDirectory(null);
		try {
			new BBCloudApi(entity).downloadSource("other-repo", "01233456789", target);
			Assertions.assertTrue(Files.list(target).count() > 0);
			BDDMockito.verify(entity).makeDownloadLink("other-repo", "01233456789");
			java.nio.file.Path limited = target.getParent().resolve("bounded-" + java.util.UUID.randomUUID());
			Assertions.assertThrows(IOException.class, () -> new BBCloudApi(entity).downloadSource("other-repo", "01233456789", limited,
					new com.tracelink.appsec.watchtower.core.scan.code.scm.api.SourceDownloadLimits(1, 1024, 10)));
			Assertions.assertFalse(Files.exists(limited));
		} finally {
			FileUtils.deleteQuietly(target.toFile());
		}
	}

	@Test
	public void testDownloadFileAtCommitByRepoAndCommit() throws IOException {
		String fileUrl = buildRequestUrl("", "repositories", "myworkspace", "other-repo", "src",
				"def456", "a/B.java");
		BDDMockito.when(entity.makeSourceFileUrl("other-repo", "def456", "a/B.java"))
				.thenReturn(apiBase + fileUrl);
		WireMock.stubFor(WireMock.get(fileUrl)
				.willReturn(WireMock.aResponse().withStatus(200).withBody("class B {}")));
		java.nio.file.Path targetDir = Files.createTempDirectory("bbtest");
		try {
			BBCloudApi api = new BBCloudApi(entity);
			api.downloadFileAtCommit("other-repo", "def456", "a/B.java", targetDir);
			Assertions.assertEquals("class B {}",
					Files.readString(targetDir.resolve("a/B.java")));
			Assertions.assertThrows(IOException.class, () -> api
					.downloadFileAtCommit("other-repo", "def456", "../escape.txt", targetDir));
		} finally {
			FileUtils.deleteQuietly(targetDir.toFile());
		}
	}

	@Test
	public void testDownloadFileAtCommitPathTraversalRejected() throws IOException {
		String filePath = "../../etc/passwd";

		java.nio.file.Path targetDir = Files.createTempDirectory("bbtest");
		try {
			BBCloudApi api = new BBCloudApi(entity);
			IOException ex = Assertions.assertThrows(IOException.class,
					() -> api.downloadFileAtCommit(mockPr, filePath, targetDir));
			MatcherAssert.assertThat(ex.getMessage(), Matchers.containsString("outside"));
			// Never reaches the network: the path is rejected before any request is built.
			WireMock.verify(0, WireMock.anyRequestedFor(WireMock.anyUrl()));
		} finally {
			FileUtils.deleteQuietly(targetDir.toFile());
		}
	}

	@Test
	public void testDownloadFileAtCommitNotFoundIsGraceful() throws IOException {
		String commitHash = "abc123";
		String filePath = "deleted/File.java";
		BDDMockito.when(mockPr.getCommitHash()).thenReturn(commitHash);
		String fileUrl = buildRequestUrl(repoBase, "src", commitHash, filePath);
		BDDMockito.when(entity.makeSourceFileUrl("repo", commitHash, filePath))
				.thenReturn(apiBase + fileUrl);
		WireMock.stubFor(
				WireMock.get(fileUrl).willReturn(WireMock.aResponse().withStatus(404)));

		java.nio.file.Path targetDir = Files.createTempDirectory("bbtest");
		try {
			BBCloudApi api = new BBCloudApi(entity);
			Assertions.assertDoesNotThrow(
					() -> api.downloadFileAtCommit(mockPr, filePath, targetDir));
			Assertions.assertFalse(Files.exists(targetDir.resolve(filePath)));
		} finally {
			FileUtils.deleteQuietly(targetDir.toFile());
		}
	}

	@Test
	public void testDownloadFileAtCommitBadResponseThrows() throws IOException {
		String commitHash = "abc123";
		String filePath = "src/main/Foo.java";
		BDDMockito.when(mockPr.getCommitHash()).thenReturn(commitHash);
		String fileUrl = buildRequestUrl(repoBase, "src", commitHash, filePath);
		BDDMockito.when(entity.makeSourceFileUrl("repo", commitHash, filePath))
				.thenReturn(apiBase + fileUrl);
		WireMock.stubFor(
				WireMock.get(fileUrl).willReturn(WireMock.aResponse().withStatus(500)));

		java.nio.file.Path targetDir = Files.createTempDirectory("bbtest");
		try {
			BBCloudApi api = new BBCloudApi(entity);
			Assertions.assertThrows(IOException.class,
					() -> api.downloadFileAtCommit(mockPr, filePath, targetDir));
		} finally {
			FileUtils.deleteQuietly(targetDir.toFile());
		}
	}

	@Test
	public void testDownloadFileAtCommitExhaustedRateLimitThrowsRateLimitedException()
			throws IOException {
		// IMPROVEMENT_PLAN.md item 4.7 - see the getChangedFilesForPullRequest
		// equivalent above for the full reasoning.
		String commitHash = "abc123";
		String filePath = "src/main/Foo.java";
		BDDMockito.when(mockPr.getCommitHash()).thenReturn(commitHash);
		String fileUrl = buildRequestUrl(repoBase, "src", commitHash, filePath);
		BDDMockito.when(entity.makeSourceFileUrl("repo", commitHash, filePath))
				.thenReturn(apiBase + fileUrl);
		WireMock.stubFor(WireMock.get(fileUrl)
				.willReturn(WireMock.aResponse().withStatus(429).withHeader("Retry-After", "15")));

		java.nio.file.Path targetDir = Files.createTempDirectory("bbtest");
		try {
			BBCloudApi api = new BBCloudApi(entity);
			RateLimitedException ex = Assertions.assertThrows(RateLimitedException.class,
					() -> api.downloadFileAtCommit(mockPr, filePath, targetDir));

			Assertions.assertEquals(15, ex.getRetryAfterSeconds());
		} finally {
			FileUtils.deleteQuietly(targetDir.toFile());
		}
	}

	/////
	// BB list files at commit tests - IMPROVEMENT_PLAN.md item 2.5b
	/////
	@Test
	public void testListFilesAtCommit() throws JSONException {
		String commitHash = "abc123";
		BDDMockito.when(mockPr.getCommitHash()).thenReturn(commitHash);
		String listingUrl = buildRequestUrl(repoBase, "src", commitHash) + "/";
		BDDMockito.when(entity.makeSourceListingUrl("repo", commitHash))
				.thenReturn(apiBase + listingUrl);

		JSONObject file1 = new JSONObject().put("path", "pom.xml").put("type", "commit_file");
		JSONObject dir = new JSONObject().put("path", "src").put("type", "commit_directory");
		JSONObject file2 =
				new JSONObject().put("path", "src/main/Foo.java").put("type", "commit_file");
		JSONObject listing = new JSONObject()
				.put("values", new JSONArray().put(file1).put(dir).put(file2));
		WireMock.stubFor(WireMock.get(WireMock.urlPathEqualTo(listingUrl))
				.willReturn(WireMock.aResponse().withStatus(200).withBody(listing.toString())));

		BBCloudApi api = new BBCloudApi(entity);
		List<String> files = api.listFilesAtCommit(mockPr);

		// Only commit_file entries, not the commit_directory entry.
		MatcherAssert.assertThat(files,
				Matchers.containsInAnyOrder("pom.xml", "src/main/Foo.java"));
	}

	@Test
	public void testListFilesAtCommitFollowsPagination() throws JSONException {
		String commitHash = "abc123";
		BDDMockito.when(mockPr.getCommitHash()).thenReturn(commitHash);
		String listingUrl = buildRequestUrl(repoBase, "src", commitHash) + "/";
		String page2Url = buildRequestUrl(repoBase, "src", commitHash, "page2");
		BDDMockito.when(entity.makeSourceListingUrl("repo", commitHash))
				.thenReturn(apiBase + listingUrl);

		JSONObject file1 = new JSONObject().put("path", "A.java").put("type", "commit_file");
		JSONObject page1 = new JSONObject().put("values", new JSONArray().put(file1))
				.put("next", apiBase + page2Url);
		WireMock.stubFor(WireMock.get(WireMock.urlPathEqualTo(listingUrl))
				.willReturn(WireMock.aResponse().withStatus(200).withBody(page1.toString())));

		JSONObject file2 = new JSONObject().put("path", "B.java").put("type", "commit_file");
		JSONObject page2 = new JSONObject().put("values", new JSONArray().put(file2));
		WireMock.stubFor(WireMock.get(WireMock.urlPathEqualTo(page2Url))
				.willReturn(WireMock.aResponse().withStatus(200).withBody(page2.toString())));

		BBCloudApi api = new BBCloudApi(entity);
		List<String> files = api.listFilesAtCommit(mockPr);

		MatcherAssert.assertThat(files, Matchers.containsInAnyOrder("A.java", "B.java"));
		WireMock.verify(WireMock.getRequestedFor(WireMock.urlPathEqualTo(page2Url)));
	}

	@Test
	public void testListFilesAtCommitNotFoundReturnsEmpty() {
		String commitHash = "abc123";
		BDDMockito.when(mockPr.getCommitHash()).thenReturn(commitHash);
		String listingUrl = buildRequestUrl(repoBase, "src", commitHash) + "/";
		BDDMockito.when(entity.makeSourceListingUrl("repo", commitHash))
				.thenReturn(apiBase + listingUrl);
		WireMock.stubFor(WireMock.get(WireMock.urlPathEqualTo(listingUrl))
				.willReturn(WireMock.aResponse().withStatus(404)));

		BBCloudApi api = new BBCloudApi(entity);
		Assertions.assertTrue(api.listFilesAtCommit(mockPr).isEmpty());
	}

	@Test
	public void testListFilesAtCommitBadResponseOnSecondPageDiscardsWholeListing() throws JSONException {
		String commitHash = "abc123";
		BDDMockito.when(mockPr.getCommitHash()).thenReturn(commitHash);
		String listingUrl = buildRequestUrl(repoBase, "src", commitHash) + "/";
		String page2Url = buildRequestUrl(repoBase, "src", commitHash, "page2");
		BDDMockito.when(entity.makeSourceListingUrl("repo", commitHash))
				.thenReturn(apiBase + listingUrl);

		JSONObject file1 = new JSONObject().put("path", "A.java").put("type", "commit_file");
		JSONObject page1 = new JSONObject().put("values", new JSONArray().put(file1))
				.put("next", apiBase + page2Url);
		WireMock.stubFor(WireMock.get(WireMock.urlPathEqualTo(listingUrl))
				.willReturn(WireMock.aResponse().withStatus(200).withBody(page1.toString())));
		WireMock.stubFor(WireMock.get(WireMock.urlPathEqualTo(page2Url))
				.willReturn(WireMock.aResponse().withStatus(500)));

		BBCloudApi api = new BBCloudApi(entity);
		// A failure partway through pagination must not silently return the partial
		// first-page result - that is as dangerous as guessing at file paths.
		Assertions.assertTrue(api.listFilesAtCommit(mockPr).isEmpty());
	}

	@Test
	public void testListFilesAtCommitRateLimitRetries() throws JSONException {
		String commitHash = "abc123";
		BDDMockito.when(mockPr.getCommitHash()).thenReturn(commitHash);
		String listingUrl = buildRequestUrl(repoBase, "src", commitHash) + "/";
		BDDMockito.when(entity.makeSourceListingUrl("repo", commitHash))
				.thenReturn(apiBase + listingUrl);

		JSONObject file1 = new JSONObject().put("path", "A.java").put("type", "commit_file");
		JSONObject listing = new JSONObject().put("values", new JSONArray().put(file1));
		WireMock.stubFor(WireMock.get(WireMock.urlPathEqualTo(listingUrl))
				.willReturn(WireMock.aResponse().withStatus(429).withHeader("Retry-After", "20"))
				.inScenario("listFilesRateLimit").whenScenarioStateIs(Scenario.STARTED)
				.willSetStateTo("ok"));
		WireMock.stubFor(WireMock.get(WireMock.urlPathEqualTo(listingUrl))
				.willReturn(WireMock.aResponse().withStatus(200).withBody(listing.toString()))
				.inScenario("listFilesRateLimit").whenScenarioStateIs("ok"));

		BBCloudApi api = new BBCloudApi(entity);
		List<String> files = api.listFilesAtCommit(mockPr);

		MatcherAssert.assertThat(files, Matchers.contains("A.java"));
	}

	@Test
	public void testListFilesAtCommitExceptionReturnsEmpty() {
		String commitHash = "abc123";
		BDDMockito.when(mockPr.getCommitHash()).thenReturn(commitHash);
		String listingUrl = buildRequestUrl(repoBase, "src", commitHash) + "/";
		BDDMockito.when(entity.makeSourceListingUrl("repo", commitHash))
				.thenReturn(apiBase + listingUrl);
		WireMock.stubFor(WireMock.get(WireMock.urlPathEqualTo(listingUrl))
				.willReturn(WireMock.aResponse().withFault(Fault.CONNECTION_RESET_BY_PEER)));

		BBCloudApi api = new BBCloudApi(entity);
		Assertions.assertTrue(api.listFilesAtCommit(mockPr).isEmpty());
	}

	/////
	// BB get data test
	/////
	@Test
	public void testUpdatePRDataNullName() throws ScanRejectedException {
		Assertions.assertThrows(ScanRejectedException.class,
				() -> {
					BDDMockito.when(mockPr.getRepoName()).thenReturn(null);
					BBCloudApi api = new BBCloudApi(entity);
					api.updatePRData(mockPr);
				});
	}

	@Test
	public void testUpdatePRData() throws ScanRejectedException, JSONException {
		String authorName = "chris";
		String branchName = "foobranch";
		String commitHash = "1234567890";
		String destBranchName = "foobarbranch";
		String id = mockPr.getPrId();
		long updateTime = System.currentTimeMillis();
		String repoName = "repo";
		JSONObject prJson =
				makePRJson(authorName, branchName, commitHash, destBranchName, updateTime, id);

		WireMock.stubFor(WireMock.get(buildRequestUrl(prBase))
				.willReturn(WireMock.aResponse().withStatus(200).withBody(prJson.toString())));

		BDDMockito.when(mockPr.getRepoName()).thenReturn(repoName);
		BDDMockito.when(entity.makeApiPRUrl(BDDMockito.anyString(), BDDMockito.anyString()))
				.thenReturn(apiBase + prBase);

		BBCloudApi api = new BBCloudApi(entity);
		PullRequest pr = api.updatePRData(mockPr);
		Assertions.assertEquals(authorName, pr.getAuthor());
		Assertions.assertEquals(branchName, pr.getSourceBranch());
		Assertions.assertEquals(destBranchName, pr.getDestinationBranch());
		Assertions.assertEquals(id, pr.getPrId());
		Assertions.assertEquals(repoName, pr.getRepoName());
	}

	@Test
	public void testUpdatePRDataRateLimit() throws ScanRejectedException, JSONException {
		String authorName = "chris";
		String branchName = "foobranch";
		String commitHash = "1234567";
		String destBranchName = "foobarbranch";
		String id = mockPr.getPrId();
		long updateTime = System.currentTimeMillis();
		String repoName = "repo";
		JSONObject prJson =
				makePRJson(authorName, branchName, commitHash, destBranchName, updateTime, id);

		WireMock.stubFor(WireMock.get(buildRequestUrl(prBase))
				.willReturn(WireMock.aResponse().withStatus(429).withHeader("Retry-After", "20"))
				.inScenario("getDataRateLimit").whenScenarioStateIs(Scenario.STARTED)
				.willSetStateTo("ok"));

		WireMock.stubFor(WireMock.get(buildRequestUrl(prBase))
				.willReturn(WireMock.aResponse().withStatus(200).withBody(prJson.toString()))
				.inScenario("getDataRateLimit").whenScenarioStateIs("ok"));

		BDDMockito.when(entity.makeApiPRUrl(BDDMockito.anyString(), BDDMockito.anyString()))
				.thenReturn(apiBase + prBase);
		BDDMockito.when(mockPr.getRepoName()).thenReturn(repoName);

		BBCloudApi api = new BBCloudApi(entity);
		PullRequest pr = api.updatePRData(mockPr);
		Assertions.assertEquals(authorName, pr.getAuthor());
		Assertions.assertEquals(branchName, pr.getSourceBranch());
		Assertions.assertEquals(destBranchName, pr.getDestinationBranch());
		Assertions.assertEquals(id, pr.getPrId());
		Assertions.assertEquals(repoName, pr.getRepoName());
	}



	@Test
	public void testUpdatePRDataPRError() throws ScanRejectedException {
		Assertions.assertThrows(ScanRejectedException.class,
				() -> {
					WireMock.stubFor(WireMock.get(buildRequestUrl(prBase))
							.willReturn(WireMock.aResponse().withStatus(400)));
					BDDMockito
							.when(entity.makeApiPRUrl(BDDMockito.anyString(),
									BDDMockito.anyString()))
							.thenReturn(apiBase + prBase);
					BBCloudApi api = new BBCloudApi(entity);

					api.updatePRData(mockPr);
				});
	}

	@Test
	public void testUpdatePRDataPRException() throws ScanRejectedException {
		Assertions.assertThrows(ScanRejectedException.class,
				() -> {
					WireMock.stubFor(
							WireMock.get(buildRequestUrl(prBase))
									.willReturn(
											WireMock.aResponse().withFault(Fault.EMPTY_RESPONSE)));
					BDDMockito
							.when(entity.makeApiPRUrl(BDDMockito.anyString(),
									BDDMockito.anyString()))
							.thenReturn(apiBase + prBase);
					BBCloudApi api = new BBCloudApi(entity);

					api.updatePRData(mockPr);
				});
	}

	/////
	// BB send comment tests
	/////
	@Test
	public void testSendComment() {
		String message = "No Violations Found";

		WireMock.stubFor(
				WireMock.post(buildRequestUrl(prBase, "comments"))
						.willReturn(WireMock.aResponse().withStatus(201)));

		BDDMockito.when(entity.makeApiPRUrl(BDDMockito.anyString(), BDDMockito.anyString()))
				.thenReturn(apiBase + prBase);
		BDDMockito.when(entity.getRejectOption()).thenReturn(BBCloudRejectOption.SEND_COMMENT);

		BBCloudApi api = new BBCloudApi(entity);
		api.sendComment(mockPr, message);
		WireMock.verify(
				WireMock.postRequestedFor(WireMock.urlEqualTo(buildRequestUrl(prBase, "comments")))
						.withRequestBody(WireMock.containing(message)));
	}

	@Test
	public void testSendCommentDoNothing() {
		String message = "No Violations Found";

		WireMock.stubFor(
				WireMock.post(buildRequestUrl(prBase, "comments"))
						.willReturn(WireMock.aResponse().withStatus(201)));

		BDDMockito.when(entity.getRejectOption()).thenReturn(BBCloudRejectOption.DO_NOTHING);

		BBCloudApi api = new BBCloudApi(entity);
		api.sendComment(mockPr, message);
		WireMock.verify(0,
				WireMock.postRequestedFor(WireMock.urlEqualTo(buildRequestUrl(prBase, "comments")))
						.withRequestBody(WireMock.containing(message)));
	}

	@Test
	public void testSendCommentRateLimit() {
		String message = "No Violations Found";

		WireMock.stubFor(WireMock.post(buildRequestUrl(prBase, "comments"))
				.willReturn(WireMock.aResponse().withStatus(429).withHeader("Retry-After", "20"))
				.inScenario("sendCommentRateLimit").whenScenarioStateIs(Scenario.STARTED)
				.willSetStateTo("ok"));

		WireMock.stubFor(
				WireMock.post(buildRequestUrl(prBase, "comments"))
						.willReturn(WireMock.aResponse().withStatus(201))
						.inScenario("sendCommentRateLimit").whenScenarioStateIs("ok"));

		BDDMockito.when(entity.makeApiPRUrl(BDDMockito.anyString(), BDDMockito.anyString()))
				.thenReturn(apiBase + prBase);
		BDDMockito.when(entity.getRejectOption()).thenReturn(BBCloudRejectOption.SEND_COMMENT);
		BBCloudApi api = new BBCloudApi(entity);
		api.sendComment(mockPr, message);
		WireMock.verify(2,
				WireMock.postRequestedFor(WireMock.urlEqualTo(buildRequestUrl(prBase, "comments")))
						.withRequestBody(WireMock.containing(message)));
	}

	@Test
	public void testSendCommentBad() {
		String message = "No Violations Found";

		WireMock.stubFor(
				WireMock.post(buildRequestUrl(prBase, "comments"))
						.willReturn(WireMock.aResponse().withStatus(400)));
		BDDMockito.when(entity.makeApiPRUrl(BDDMockito.anyString(), BDDMockito.anyString()))
				.thenReturn(apiBase + prBase);
		BDDMockito.when(entity.getRejectOption()).thenReturn(BBCloudRejectOption.SEND_COMMENT);

		BBCloudApi api = new BBCloudApi(entity);
		api.sendComment(mockPr, message);
		WireMock.verify(
				WireMock.postRequestedFor(WireMock.urlEqualTo(buildRequestUrl(prBase, "comments")))
						.withRequestBody(WireMock.containing(message)));
		Assertions.assertTrue(logWatcher.getMessages().get(0).contains("sending report"));
	}

	@Test
	public void testSendCommentException() {
		String message = "No Violations Found";

		WireMock.stubFor(WireMock.post(buildRequestUrl(prBase, "comments"))
				.willReturn(WireMock.aResponse().withFault(Fault.CONNECTION_RESET_BY_PEER)));
		BDDMockito.when(entity.makeApiPRUrl(BDDMockito.anyString(), BDDMockito.anyString()))
				.thenReturn(apiBase + prBase);
		BDDMockito.when(entity.getRejectOption()).thenReturn(BBCloudRejectOption.SEND_COMMENT);

		BBCloudApi api = new BBCloudApi(entity);
		api.sendComment(mockPr, message);
		WireMock.verify(
				WireMock.postRequestedFor(WireMock.urlEqualTo(buildRequestUrl(prBase, "comments")))
						.withRequestBody(WireMock.containing(message)));
		Assertions.assertTrue(
				logWatcher.getMessages().get(0).contains("Exception while sending report"));
	}

	/////
	// BB decline PR tests
	/////

	@Test
	public void testBlockPR() {
		WireMock.stubFor(
				WireMock.post(buildRequestUrl(prBase, "decline"))
						.willReturn(WireMock.aResponse().withStatus(200)));
		BDDMockito.when(entity.makeApiPRUrl(BDDMockito.anyString(), BDDMockito.anyString()))
				.thenReturn(apiBase + prBase);
		BDDMockito.when(entity.getRejectOption()).thenReturn(BBCloudRejectOption.BLOCK_PR);
		BBCloudApi api = new BBCloudApi(entity);
		api.blockPR(mockPr);
		WireMock.verify(
				WireMock.postRequestedFor(WireMock.urlEqualTo(buildRequestUrl(prBase, "decline"))));
	}

	@Test
	public void testBlockPRBadOption() {
		WireMock.stubFor(
				WireMock.post(buildRequestUrl(prBase, "decline"))
						.willReturn(WireMock.aResponse().withStatus(200)));
		BDDMockito.when(entity.getRejectOption()).thenReturn(BBCloudRejectOption.SEND_COMMENT);
		BBCloudApi api = new BBCloudApi(entity);
		api.blockPR(mockPr);
		WireMock.verify(0,
				WireMock.postRequestedFor(WireMock.urlEqualTo(buildRequestUrl(prBase, "decline"))));
	}

	@Test
	public void testBlockPRRateLimit() {
		BDDMockito.when(entity.makeApiPRUrl(BDDMockito.anyString(), BDDMockito.anyString()))
				.thenReturn(apiBase + prBase);
		BDDMockito.when(entity.getRejectOption()).thenReturn(BBCloudRejectOption.BLOCK_PR);
		WireMock.stubFor(WireMock.post(buildRequestUrl(prBase, "decline"))
				.willReturn(WireMock.aResponse().withStatus(429).withHeader("Retry-After", "20"))
				.inScenario("sendDeclineRateLimit").whenScenarioStateIs(Scenario.STARTED)
				.willSetStateTo("ok"));

		WireMock.stubFor(
				WireMock.post(buildRequestUrl(prBase, "decline"))
						.willReturn(WireMock.aResponse().withStatus(200))
						.inScenario("sendDeclineRateLimit").whenScenarioStateIs("ok"));

		BBCloudApi api = new BBCloudApi(entity);
		api.blockPR(mockPr);
		WireMock.verify(2,
				WireMock.postRequestedFor(WireMock.urlEqualTo(buildRequestUrl(prBase, "decline"))));
	}

	@Test
	public void testBlockPRBad() {
		WireMock.stubFor(
				WireMock.post(buildRequestUrl(prBase, "decline"))
						.willReturn(WireMock.aResponse().withStatus(400)));
		BDDMockito.when(entity.makeApiPRUrl(BDDMockito.anyString(), BDDMockito.anyString()))
				.thenReturn(apiBase + prBase);
		BDDMockito.when(entity.getRejectOption()).thenReturn(BBCloudRejectOption.BLOCK_PR);

		BBCloudApi api = new BBCloudApi(entity);
		api.blockPR(mockPr);
		WireMock.verify(
				WireMock.postRequestedFor(WireMock.urlEqualTo(buildRequestUrl(prBase, "decline"))));
		Assertions.assertTrue(logWatcher.getMessages().get(0).contains(" while declining PR "));
	}

	@Test
	public void testBlockPRException() {
		WireMock.stubFor(WireMock.post(buildRequestUrl(prBase, "decline"))
				.willReturn(WireMock.aResponse().withFault(Fault.CONNECTION_RESET_BY_PEER)));
		BDDMockito.when(entity.makeApiPRUrl(BDDMockito.anyString(), BDDMockito.anyString()))
				.thenReturn(apiBase + prBase);
		BDDMockito.when(entity.getRejectOption()).thenReturn(BBCloudRejectOption.BLOCK_PR);
		BBCloudApi api = new BBCloudApi(entity);
		api.blockPR(mockPr);
		WireMock.verify(
				WireMock.postRequestedFor(WireMock.urlEqualTo(buildRequestUrl(prBase, "decline"))));
		Assertions.assertTrue(
				logWatcher.getMessages().get(0).contains("Exception while declining PR"));
	}

	/////
	// BB review state (approve / request changes) tests
	/////

	@Test
	public void testSendCommentWithApproveOrRequestChangesOption() {
		WireMock.stubFor(WireMock.post(buildRequestUrl(prBase, "comments"))
				.willReturn(WireMock.aResponse().withStatus(201)));
		BDDMockito.when(entity.makeApiPRUrl(BDDMockito.anyString(), BDDMockito.anyString()))
				.thenReturn(apiBase + prBase);
		BDDMockito.when(entity.getRejectOption())
				.thenReturn(BBCloudRejectOption.APPROVE_OR_REQUEST_CHANGES);

		new BBCloudApi(entity).sendComment(mockPr, "report");

		WireMock.verify(
				WireMock.postRequestedFor(WireMock.urlEqualTo(buildRequestUrl(prBase, "comments"))));
	}

	@Test
	public void testBlockPRSkippedForApproveOrRequestChangesOption() {
		BDDMockito.when(entity.getRejectOption())
				.thenReturn(BBCloudRejectOption.APPROVE_OR_REQUEST_CHANGES);

		new BBCloudApi(entity).blockPR(mockPr);

		WireMock.verify(0,
				WireMock.postRequestedFor(WireMock.urlEqualTo(buildRequestUrl(prBase, "decline"))));
	}

	@Test
	public void testApprovePRClearsRequestChangesThenApproves() {
		stubReview(204, 200);
		BDDMockito.when(entity.makeApiPRUrl(BDDMockito.anyString(), BDDMockito.anyString()))
				.thenReturn(apiBase + prBase);
		BDDMockito.when(entity.getRejectOption())
				.thenReturn(BBCloudRejectOption.APPROVE_OR_REQUEST_CHANGES);

		new BBCloudApi(entity).approvePR(mockPr);

		WireMock.verify(WireMock.deleteRequestedFor(
				WireMock.urlEqualTo(buildRequestUrl(prBase, "request-changes"))));
		WireMock.verify(WireMock.postRequestedFor(
				WireMock.urlEqualTo(buildRequestUrl(prBase, "approve"))));
		Assertions.assertTrue(logWatcher.getMessages().isEmpty(), logWatcher.getMessages().toString());
	}

	@Test
	public void testApprovePRTreatsMissingRequestChangesAsNothingToClear() {
		stubReview(404, 200);
		BDDMockito.when(entity.makeApiPRUrl(BDDMockito.anyString(), BDDMockito.anyString()))
				.thenReturn(apiBase + prBase);
		BDDMockito.when(entity.getRejectOption())
				.thenReturn(BBCloudRejectOption.APPROVE_OR_REQUEST_CHANGES);

		new BBCloudApi(entity).approvePR(mockPr);

		WireMock.verify(WireMock.postRequestedFor(
				WireMock.urlEqualTo(buildRequestUrl(prBase, "approve"))));
		Assertions.assertTrue(logWatcher.getMessages().isEmpty(), logWatcher.getMessages().toString());
	}

	@Test
	public void testRequestChangesPRClearsApprovalThenRequestsChanges() {
		stubHead(HEAD_COMMIT);
		WireMock.stubFor(WireMock.delete(buildRequestUrl(prBase, "approve"))
				.willReturn(WireMock.aResponse().withStatus(204)));
		WireMock.stubFor(WireMock.post(buildRequestUrl(prBase, "request-changes"))
				.willReturn(WireMock.aResponse().withStatus(200)));
		BDDMockito.when(entity.makeApiPRUrl(BDDMockito.anyString(), BDDMockito.anyString()))
				.thenReturn(apiBase + prBase);
		BDDMockito.when(entity.getRejectOption())
				.thenReturn(BBCloudRejectOption.APPROVE_OR_REQUEST_CHANGES);

		new BBCloudApi(entity).requestChangesPR(mockPr);

		WireMock.verify(WireMock.deleteRequestedFor(
				WireMock.urlEqualTo(buildRequestUrl(prBase, "approve"))));
		WireMock.verify(WireMock.postRequestedFor(
				WireMock.urlEqualTo(buildRequestUrl(prBase, "request-changes"))));
	}

	@Test
	public void testReviewActionsSkippedForOtherOptions() {
		for (BBCloudRejectOption option : new BBCloudRejectOption[] {
				BBCloudRejectOption.DO_NOTHING, BBCloudRejectOption.SEND_COMMENT,
				BBCloudRejectOption.BLOCK_PR}) {
			BDDMockito.when(entity.getRejectOption()).thenReturn(option);
			BBCloudApi api = new BBCloudApi(entity);
			api.approvePR(mockPr);
			api.requestChangesPR(mockPr);
		}

		WireMock.verify(0, WireMock.anyRequestedFor(WireMock.anyUrl()));
	}

	@Test
	public void testApprovePRRateLimit() {
		stubHead(HEAD_COMMIT);
		WireMock.stubFor(WireMock.delete(buildRequestUrl(prBase, "request-changes"))
				.willReturn(WireMock.aResponse().withStatus(204)));
		WireMock.stubFor(WireMock.post(buildRequestUrl(prBase, "approve"))
				.willReturn(WireMock.aResponse().withStatus(429).withHeader("Retry-After", "20"))
				.inScenario("approveRateLimit").whenScenarioStateIs(Scenario.STARTED)
				.willSetStateTo("ok"));
		WireMock.stubFor(WireMock.post(buildRequestUrl(prBase, "approve"))
				.willReturn(WireMock.aResponse().withStatus(200))
				.inScenario("approveRateLimit").whenScenarioStateIs("ok"));
		BDDMockito.when(entity.makeApiPRUrl(BDDMockito.anyString(), BDDMockito.anyString()))
				.thenReturn(apiBase + prBase);
		BDDMockito.when(entity.getRejectOption())
				.thenReturn(BBCloudRejectOption.APPROVE_OR_REQUEST_CHANGES);

		new BBCloudApi(entity).approvePR(mockPr);

		WireMock.verify(2, WireMock.postRequestedFor(
				WireMock.urlEqualTo(buildRequestUrl(prBase, "approve"))));
	}

	@Test
	public void testApprovePRBadResponseLogged() {
		stubReview(204, 400);
		BDDMockito.when(entity.makeApiPRUrl(BDDMockito.anyString(), BDDMockito.anyString()))
				.thenReturn(apiBase + prBase);
		BDDMockito.when(entity.getRejectOption())
				.thenReturn(BBCloudRejectOption.APPROVE_OR_REQUEST_CHANGES);

		new BBCloudApi(entity).approvePR(mockPr);

		Assertions.assertTrue(logWatcher.getMessages().get(0).contains(" while approving PR "));
	}

	@Test
	public void testRequestChangesPRExceptionLogged() {
		stubHead(HEAD_COMMIT);
		WireMock.stubFor(WireMock.delete(buildRequestUrl(prBase, "approve"))
				.willReturn(WireMock.aResponse().withStatus(204)));
		WireMock.stubFor(WireMock.post(buildRequestUrl(prBase, "request-changes"))
				.willReturn(WireMock.aResponse().withFault(Fault.CONNECTION_RESET_BY_PEER)));
		BDDMockito.when(entity.makeApiPRUrl(BDDMockito.anyString(), BDDMockito.anyString()))
				.thenReturn(apiBase + prBase);
		BDDMockito.when(entity.getRejectOption())
				.thenReturn(BBCloudRejectOption.APPROVE_OR_REQUEST_CHANGES);

		new BBCloudApi(entity).requestChangesPR(mockPr);

		Assertions.assertTrue(logWatcher.getMessages().get(0)
				.contains("Exception while requesting changes on PR"));
	}

	@Test
	public void testApprovePRSkippedWhenHeadCommitMoved() {
		stubReview(204, 200);
		stubHead("ffffffffff");
		BDDMockito.when(mockPr.getCommitHash()).thenReturn(HEAD_COMMIT);
		BDDMockito.when(entity.makeApiPRUrl(BDDMockito.anyString(), BDDMockito.anyString()))
				.thenReturn(apiBase + prBase);
		BDDMockito.when(entity.getRejectOption())
				.thenReturn(BBCloudRejectOption.APPROVE_OR_REQUEST_CHANGES);

		BBCloudApi api = new BBCloudApi(entity);
		api.approvePR(mockPr);
		api.requestChangesPR(mockPr);

		WireMock.verify(0, WireMock.postRequestedFor(WireMock.urlMatching(".*/(approve|request-changes)")));
		WireMock.verify(0, WireMock.deleteRequestedFor(WireMock.anyUrl()));
		Assertions.assertTrue(logWatcher.getMessages().stream()
				.anyMatch(m -> m.contains("newer commit")), logWatcher.getMessages().toString());
	}

	@Test
	public void testApprovePRSkippedWhenHeadCommitUnknown() {
		WireMock.stubFor(WireMock.get(buildRequestUrl(prBase))
				.willReturn(WireMock.aResponse().withStatus(500)));
		BDDMockito.when(mockPr.getCommitHash()).thenReturn(HEAD_COMMIT);
		BDDMockito.when(entity.makeApiPRUrl(BDDMockito.anyString(), BDDMockito.anyString()))
				.thenReturn(apiBase + prBase);
		BDDMockito.when(entity.getRejectOption())
				.thenReturn(BBCloudRejectOption.APPROVE_OR_REQUEST_CHANGES);

		new BBCloudApi(entity).approvePR(mockPr);

		WireMock.verify(0, WireMock.postRequestedFor(WireMock.urlMatching(".*/approve")));
		Assertions.assertTrue(logWatcher.getMessages().stream()
				.anyMatch(m -> m.contains("Cannot confirm head commit")),
				logWatcher.getMessages().toString());
	}

	/////
	// Outcome reporting: false only when a call was attempted and failed
	/////

	@Test
	public void testSendCommentReportsSuccessAndConfiguredSkipAsDone() {
		WireMock.stubFor(WireMock.post(buildRequestUrl(prBase, "comments"))
				.willReturn(WireMock.aResponse().withStatus(201)));
		BDDMockito.when(entity.makeApiPRUrl(BDDMockito.anyString(), BDDMockito.anyString()))
				.thenReturn(apiBase + prBase);
		BDDMockito.when(entity.getRejectOption()).thenReturn(BBCloudRejectOption.SEND_COMMENT,
				BBCloudRejectOption.DO_NOTHING);
		BBCloudApi api = new BBCloudApi(entity);

		Assertions.assertTrue(api.sendComment(mockPr, "report"));
		Assertions.assertTrue(api.sendComment(mockPr, "report"));
	}

	@Test
	public void testSendCommentReportsBadResponseAndExceptionAsFailed() {
		WireMock.stubFor(WireMock.post(buildRequestUrl(prBase, "comments"))
				.willReturn(WireMock.aResponse().withStatus(400))
				.inScenario("commentFails").whenScenarioStateIs(Scenario.STARTED)
				.willSetStateTo("reset"));
		WireMock.stubFor(WireMock.post(buildRequestUrl(prBase, "comments"))
				.willReturn(WireMock.aResponse().withFault(Fault.CONNECTION_RESET_BY_PEER))
				.inScenario("commentFails").whenScenarioStateIs("reset"));
		BDDMockito.when(entity.makeApiPRUrl(BDDMockito.anyString(), BDDMockito.anyString()))
				.thenReturn(apiBase + prBase);
		BDDMockito.when(entity.getRejectOption()).thenReturn(BBCloudRejectOption.SEND_COMMENT);
		BBCloudApi api = new BBCloudApi(entity);

		Assertions.assertFalse(api.sendComment(mockPr, "report"));
		Assertions.assertFalse(api.sendComment(mockPr, "report"));
	}

	@Test
	public void testBlockPRReportsOutcome() {
		WireMock.stubFor(WireMock.post(buildRequestUrl(prBase, "decline"))
				.willReturn(WireMock.aResponse().withStatus(200))
				.inScenario("decline").whenScenarioStateIs(Scenario.STARTED)
				.willSetStateTo("bad"));
		WireMock.stubFor(WireMock.post(buildRequestUrl(prBase, "decline"))
				.willReturn(WireMock.aResponse().withStatus(400))
				.inScenario("decline").whenScenarioStateIs("bad"));
		BDDMockito.when(entity.makeApiPRUrl(BDDMockito.anyString(), BDDMockito.anyString()))
				.thenReturn(apiBase + prBase);
		BDDMockito.when(entity.getRejectOption()).thenReturn(BBCloudRejectOption.BLOCK_PR,
				BBCloudRejectOption.BLOCK_PR, BBCloudRejectOption.SEND_COMMENT);
		BBCloudApi api = new BBCloudApi(entity);

		Assertions.assertTrue(api.blockPR(mockPr));
		Assertions.assertFalse(api.blockPR(mockPr));
		Assertions.assertTrue(api.blockPR(mockPr), "skipped by configuration is not a failure");
	}

	@Test
	public void testApprovePRReportsOutcome() {
		stubReview(204, 200);
		BDDMockito.when(entity.makeApiPRUrl(BDDMockito.anyString(), BDDMockito.anyString()))
				.thenReturn(apiBase + prBase);
		BDDMockito.when(entity.getRejectOption())
				.thenReturn(BBCloudRejectOption.APPROVE_OR_REQUEST_CHANGES);
		BBCloudApi api = new BBCloudApi(entity);
		Assertions.assertTrue(api.approvePR(mockPr));

		stubReview(204, 400);
		Assertions.assertFalse(api.approvePR(mockPr));
	}

	@Test
	public void testReviewActionsSkippedForOtherOptionsAreNotFailures() {
		BDDMockito.when(entity.getRejectOption()).thenReturn(BBCloudRejectOption.SEND_COMMENT);
		BBCloudApi api = new BBCloudApi(entity);

		Assertions.assertTrue(api.approvePR(mockPr));
		Assertions.assertTrue(api.requestChangesPR(mockPr));
	}

	@Test
	public void testReviewActionSkippedForANewerHeadIsNotAFailure() {
		stubHead("ffffffffff");
		BDDMockito.when(entity.makeApiPRUrl(BDDMockito.anyString(), BDDMockito.anyString()))
				.thenReturn(apiBase + prBase);
		BDDMockito.when(entity.getRejectOption())
				.thenReturn(BBCloudRejectOption.APPROVE_OR_REQUEST_CHANGES);

		Assertions.assertTrue(new BBCloudApi(entity).requestChangesPR(mockPr));
	}

	@Test
	public void testReviewActionIsAFailureWhenTheHeadCannotBeConfirmed() {
		// Review state is left as it was, so a stale "changes requested" could keep blocking.
		WireMock.stubFor(WireMock.get(buildRequestUrl(prBase))
				.willReturn(WireMock.aResponse().withStatus(500)));
		BDDMockito.when(mockPr.getCommitHash()).thenReturn(HEAD_COMMIT);
		BDDMockito.when(entity.makeApiPRUrl(BDDMockito.anyString(), BDDMockito.anyString()))
				.thenReturn(apiBase + prBase);
		BDDMockito.when(entity.getRejectOption())
				.thenReturn(BBCloudRejectOption.APPROVE_OR_REQUEST_CHANGES);

		Assertions.assertFalse(new BBCloudApi(entity).approvePR(mockPr));
	}

	@Test
	public void testRequestChangesPRExceptionIsAFailure() {
		stubHead(HEAD_COMMIT);
		WireMock.stubFor(WireMock.delete(buildRequestUrl(prBase, "approve"))
				.willReturn(WireMock.aResponse().withStatus(204)));
		WireMock.stubFor(WireMock.post(buildRequestUrl(prBase, "request-changes"))
				.willReturn(WireMock.aResponse().withFault(Fault.CONNECTION_RESET_BY_PEER)));
		BDDMockito.when(entity.makeApiPRUrl(BDDMockito.anyString(), BDDMockito.anyString()))
				.thenReturn(apiBase + prBase);
		BDDMockito.when(entity.getRejectOption())
				.thenReturn(BBCloudRejectOption.APPROVE_OR_REQUEST_CHANGES);

		Assertions.assertFalse(new BBCloudApi(entity).requestChangesPR(mockPr));
	}

	private void stubHead(String headCommit) {
		BDDMockito.when(mockPr.getCommitHash()).thenReturn(HEAD_COMMIT);
		try {
			WireMock.stubFor(WireMock.get(buildRequestUrl(prBase))
					.willReturn(WireMock.aResponse().withStatus(200).withBody(makePRJson("chris",
							"foobranch", headCommit, "main", System.currentTimeMillis(),
							mockPr.getPrId()).toString())));
		} catch (JSONException e) {
			throw new IllegalStateException(e);
		}
	}

	private void stubReview(int clearStatus, int approveStatus) {
		stubHead(HEAD_COMMIT);
		WireMock.stubFor(WireMock.delete(buildRequestUrl(prBase, "request-changes"))
				.willReturn(WireMock.aResponse().withStatus(clearStatus)));
		WireMock.stubFor(WireMock.post(buildRequestUrl(prBase, "approve"))
				.willReturn(WireMock.aResponse().withStatus(approveStatus)));
	}

	/////
	// BB get Pull Requests
	/////

	@Test
	public void testGetOpenPullRequestsForRepository() throws JSONException {
		String authorName = "chris";
		String branchName = "foobranch";
		String commitHash = "1234567";
		String destBranchName = "foobarbranch";
		String id = mockPr.getPrId();
		String repoName = "repo";
		long updateTime = System.currentTimeMillis();
		String url = buildRequestUrl(workspaceUrl, repoName, "pullrequests");
		JSONObject prJson =
				makePRJson(authorName, branchName, commitHash, destBranchName, updateTime, id);
		JSONObject repoPrJson = new JSONObject()
				.put("values", new JSONArray().put(prJson));

		WireMock.stubFor(WireMock.get(WireMock.urlPathEqualTo(url))
				.willReturn(WireMock.aResponse().withStatus(200).withBody(repoPrJson.toString())));
		BDDMockito.when(entity.makeApiWorkspaceUrl())
				.thenReturn(apiBase + workspaceUrl);

		BBCloudApi api = new BBCloudApi(entity);
		List<PullRequest> openPrs = api.getOpenPullRequestsForRepository(repoName);
		Assertions.assertEquals(1, openPrs.size());
		PullRequest pr = openPrs.get(0);
		Assertions.assertEquals(authorName, pr.getAuthor());
		Assertions.assertEquals(branchName, pr.getSourceBranch());
		Assertions.assertEquals(destBranchName, pr.getDestinationBranch());
		Assertions.assertEquals(id, pr.getPrId());
		Assertions.assertEquals(repoName, pr.getRepoName());
	}

	@Test
	public void testGetOpenPullRequestsForRepositoryRateLimit() throws JSONException {
		String authorName = "chris";
		String branchName = "foobranch";
		String commitHash = "1234567";
		String destBranchName = "foobarbranch";
		String id = mockPr.getPrId();
		String repoName = "repo";
		long updateTime = System.currentTimeMillis();
		String url = buildRequestUrl(workspaceUrl, repoName, "pullrequests");
		JSONObject prJson =
				makePRJson(authorName, branchName, commitHash, destBranchName, updateTime, id);
		JSONObject repoPrJson = new JSONObject()
				.put("values", new JSONArray().put(prJson));

		BDDMockito.when(entity.makeApiWorkspaceUrl())
				.thenReturn(apiBase + workspaceUrl);

		WireMock.stubFor(WireMock.get(WireMock.urlPathEqualTo(url))
				.willReturn(WireMock.aResponse().withStatus(429))
				.inScenario("getOpenPRRateLimit").whenScenarioStateIs(Scenario.STARTED)
				.willSetStateTo("ok"));

		WireMock.stubFor(WireMock.get(WireMock.urlPathEqualTo(url))
				.willReturn(WireMock.aResponse().withStatus(200).withBody(repoPrJson.toString()))
				.inScenario("getOpenPRRateLimit").whenScenarioStateIs("ok"));

		BBCloudApi api = new BBCloudApi(entity);

		List<PullRequest> openPrs = api.getOpenPullRequestsForRepository(repoName);
		Assertions.assertEquals(1, openPrs.size());
		PullRequest pr = openPrs.get(0);
		Assertions.assertEquals(authorName, pr.getAuthor());
		Assertions.assertEquals(branchName, pr.getSourceBranch());
		Assertions.assertEquals(destBranchName, pr.getDestinationBranch());
		Assertions.assertEquals(id, pr.getPrId());
		Assertions.assertEquals(repoName, pr.getRepoName());
	}

	@Test
	public void testGetOpenPullRequestsForRepository404() throws JSONException {
		String repoName = "repo";
		String url = buildRequestUrl(workspaceUrl, repoName, "pullrequests");

		WireMock.stubFor(WireMock.get(WireMock.urlPathEqualTo(url))
				.willReturn(WireMock.aResponse().withStatus(404)));

		BDDMockito.when(entity.makeApiWorkspaceUrl())
				.thenReturn(apiBase + workspaceUrl);

		BBCloudApi api = new BBCloudApi(entity);
		List<PullRequest> openPrs = api.getOpenPullRequestsForRepository(repoName);
		Assertions.assertEquals(0, openPrs.size());
		MatcherAssert.assertThat(logWatcher.getMessages().get(0),
				Matchers.containsString("Bad response"));
	}

	@Test
	public void testGetOpenPullRequestsForRepositoryException() throws JSONException {
		String repoName = "repo";
		String url = buildRequestUrl(workspaceUrl, repoName, "pullrequests");

		WireMock.stubFor(WireMock.get(WireMock.urlPathEqualTo(url))
				.willReturn(WireMock.aResponse().withFault(Fault.CONNECTION_RESET_BY_PEER)));
		BDDMockito.when(entity.makeApiWorkspaceUrl())
				.thenReturn(apiBase + workspaceUrl);

		BBCloudApi api = new BBCloudApi(entity);
		List<PullRequest> openPrs = api.getOpenPullRequestsForRepository(repoName);
		Assertions.assertEquals(0, openPrs.size());
		MatcherAssert.assertThat(logWatcher.getMessages().get(0),
				Matchers.containsString("Exception while getting PRs for repository"));
	}



	/////
	// BB webhook self-registration (IMPROVEMENT_PLAN.md item 8)
	/////

	@Test
	public void testRegisterCreatesNewHookWhenNoneExists() throws JSONException {
		BDDMockito.when(entity.makeWorkspaceHooksUrl()).thenReturn(apiBase + hooksUrl);
		BDDMockito.when(entity.getApiLabel()).thenReturn("myapilabel");

		JSONObject emptyList = new JSONObject().put("values", new JSONArray());
		WireMock.stubFor(WireMock.get(WireMock.urlPathEqualTo(hooksUrl))
				.willReturn(WireMock.aResponse().withStatus(200).withBody(emptyList.toString())));

		JSONObject created = new JSONObject().put("uuid", "new-hook-uuid");
		WireMock.stubFor(WireMock.post(WireMock.urlPathEqualTo(hooksUrl))
				.willReturn(WireMock.aResponse().withStatus(201).withBody(created.toString())));

		BBCloudApi api = new BBCloudApi(entity);
		api.register(mockPasswordEncoder, "https://watchtower.example.com");

		WireMock.verify(WireMock.postRequestedFor(WireMock.urlPathEqualTo(hooksUrl))
				.withRequestBody(WireMock.matchingJsonPath("$.secret"))
				.withRequestBody(WireMock.containing(
						"https://watchtower.example.com/rest/scan/myapilabel"))
				.withRequestBody(WireMock.containing("pullrequest:fulfilled"))
				// "/watchtower bypass <reason>" comments (§4.18)
				.withRequestBody(WireMock.containing("pullrequest:comment_created")));
		BDDMockito.verify(entity).setWebhookUuid("new-hook-uuid");
		BDDMockito.verify(entity).setWebhookSecret(BDDMockito.anyString());
	}

	@Test
	public void testRegisterUpdatesExistingHookInsteadOfDuplicating() throws JSONException {
		BDDMockito.when(entity.makeWorkspaceHooksUrl()).thenReturn(apiBase + hooksUrl);
		BDDMockito.when(entity.getApiLabel()).thenReturn("myapilabel");

		String callbackUrl = "https://watchtower.example.com/rest/scan/myapilabel";
		JSONObject existingHook =
				new JSONObject().put("uuid", "existing-hook-uuid").put("url", callbackUrl);
		JSONObject listing = new JSONObject().put("values", new JSONArray().put(existingHook));
		WireMock.stubFor(WireMock.get(WireMock.urlPathEqualTo(hooksUrl))
				.willReturn(WireMock.aResponse().withStatus(200).withBody(listing.toString())));

		String updateUrl = buildRequestUrl(hooksUrl, "existing-hook-uuid");
		JSONObject updated = new JSONObject().put("uuid", "existing-hook-uuid");
		WireMock.stubFor(WireMock.put(WireMock.urlPathEqualTo(updateUrl))
				.willReturn(WireMock.aResponse().withStatus(200).withBody(updated.toString())));

		BBCloudApi api = new BBCloudApi(entity);
		api.register(mockPasswordEncoder, "https://watchtower.example.com");

		WireMock.verify(WireMock.putRequestedFor(WireMock.urlPathEqualTo(updateUrl)));
		WireMock.verify(0, WireMock.postRequestedFor(WireMock.urlPathEqualTo(hooksUrl)));
		BDDMockito.verify(entity).setWebhookUuid("existing-hook-uuid");
	}

	@Test
	public void testRegisterBadResponseThrows() throws JSONException {
		BDDMockito.when(entity.makeWorkspaceHooksUrl()).thenReturn(apiBase + hooksUrl);
		BDDMockito.when(entity.getApiLabel()).thenReturn("myapilabel");

		JSONObject emptyList = new JSONObject().put("values", new JSONArray());
		WireMock.stubFor(WireMock.get(WireMock.urlPathEqualTo(hooksUrl))
				.willReturn(WireMock.aResponse().withStatus(200).withBody(emptyList.toString())));
		WireMock.stubFor(WireMock.post(WireMock.urlPathEqualTo(hooksUrl))
				.willReturn(WireMock.aResponse().withStatus(401)));

		BBCloudApi api = new BBCloudApi(entity);
		Assertions.assertThrows(IllegalStateException.class,
				() -> api.register(mockPasswordEncoder, "https://watchtower.example.com"));
		BDDMockito.verify(entity, BDDMockito.never()).setWebhookUuid(BDDMockito.anyString());
	}

	@Test
	public void testUnregisterDeletesHook() {
		BDDMockito.when(entity.makeWorkspaceHooksUrl()).thenReturn(apiBase + hooksUrl);
		BDDMockito.when(entity.getWebhookUuid()).thenReturn("existing-hook-uuid");

		String deleteUrl = buildRequestUrl(hooksUrl, "existing-hook-uuid");
		WireMock.stubFor(WireMock.delete(WireMock.urlPathEqualTo(deleteUrl))
				.willReturn(WireMock.aResponse().withStatus(204)));

		BBCloudApi api = new BBCloudApi(entity);
		api.unregister();

		WireMock.verify(WireMock.deleteRequestedFor(WireMock.urlPathEqualTo(deleteUrl)));
		BDDMockito.verify(entity).setWebhookUuid(null);
		BDDMockito.verify(entity, BDDMockito.never()).setWebhookSecret(BDDMockito.any());
	}

	@Test
	public void testUnregisterWithNoHookIsNoop() {
		BDDMockito.when(entity.getWebhookUuid()).thenReturn(null);

		BBCloudApi api = new BBCloudApi(entity);
		api.unregister();

		WireMock.verify(0, WireMock.deleteRequestedFor(WireMock.anyUrl()));
		BDDMockito.verify(entity, BDDMockito.never()).setWebhookUuid(BDDMockito.any());
	}

	@Test
	public void testUnregister404IsGraceful() {
		BDDMockito.when(entity.makeWorkspaceHooksUrl()).thenReturn(apiBase + hooksUrl);
		BDDMockito.when(entity.getWebhookUuid()).thenReturn("already-gone-uuid");

		String deleteUrl = buildRequestUrl(hooksUrl, "already-gone-uuid");
		WireMock.stubFor(WireMock.delete(WireMock.urlPathEqualTo(deleteUrl))
				.willReturn(WireMock.aResponse().withStatus(404)));

		BBCloudApi api = new BBCloudApi(entity);
		api.unregister();

		BDDMockito.verify(entity).setWebhookUuid(null);
		BDDMockito.verify(entity, BDDMockito.never()).setWebhookSecret(BDDMockito.any());
	}

	@Test
	public void testUnregisterBadResponseThrows() {
		BDDMockito.when(entity.makeWorkspaceHooksUrl()).thenReturn(apiBase + hooksUrl);
		BDDMockito.when(entity.getWebhookUuid()).thenReturn("existing-hook-uuid");

		String deleteUrl = buildRequestUrl(hooksUrl, "existing-hook-uuid");
		WireMock.stubFor(WireMock.delete(WireMock.urlPathEqualTo(deleteUrl))
				.willReturn(WireMock.aResponse().withStatus(400)));

		BBCloudApi api = new BBCloudApi(entity);
		Assertions.assertThrows(IllegalStateException.class, api::unregister);
		BDDMockito.verify(entity, BDDMockito.never()).setWebhookUuid(null);
	}

	/////
	// Helpers
	/////
	private JSONObject makePRJson(String authorName, String branchName, String commitHash,
			String destBranchName, long updateDate, String id) throws JSONException {
		JSONObject prJson = new JSONObject()
				.put("author", new JSONObject().put("display_name", authorName))
				//
				.put("source",
						new JSONObject().put("branch", new JSONObject().put("name", branchName))
								.put("commit", new JSONObject().put("hash", commitHash)))
				//
				.put("destination",
						new JSONObject().put("branch",
								new JSONObject().put("name", destBranchName)))
				//
				.put("id", Integer.parseInt(id))
				//
				.put("updated_on",
						Instant.ofEpochMilli(updateDate).atOffset(ZoneOffset.UTC)
								.format(DateTimeFormatter.ISO_OFFSET_DATE_TIME))
				//
				.put("state", "OPEN");
		return prJson;
	}

	/////
	// Inline comment sync (§4.14): list, post inline, edit, delete
	/////

	private void givenCommentingIntegration() {
		BDDMockito.when(entity.makeApiPRUrl(BDDMockito.anyString(), BDDMockito.anyString()))
				.thenReturn(apiBase + prBase);
		BDDMockito.when(entity.getRejectOption())
				.thenReturn(BBCloudRejectOption.APPROVE_OR_REQUEST_CHANGES);
	}

	private static JSONObject commentJson(long id, String raw, String path, Integer line,
			boolean deleted) throws JSONException {
		JSONObject comment = new JSONObject().put("id", id).put("deleted", deleted)
				.put("content", new JSONObject().put("raw", raw));
		if (path != null) {
			comment.put("inline", new JSONObject().put("path", path).put("to", line));
		}
		return comment;
	}

	@Test
	public void testListCommentsFollowsPagesAndSkipsDeleted() throws JSONException {
		givenCommentingIntegration();
		String commentsUrl = buildRequestUrl(prBase, "comments");
		String page2 = apiBase + commentsUrl + "?page=2";
		WireMock.stubFor(WireMock.get(WireMock.urlPathEqualTo(commentsUrl))
				.withQueryParam("pagelen", WireMock.equalTo("100"))
				.willReturn(WireMock.aResponse().withStatus(200)
						.withHeader("Content-Type", "application/json")
						.withBody(new JSONObject()
								.put("values", new JSONArray()
										.put(commentJson(1, "summary", null, null, false))
										.put(commentJson(2, "inline", "a.yml", 12, false)))
								.put("next", page2).toString())));
		WireMock.stubFor(WireMock.get(WireMock.urlPathEqualTo(commentsUrl))
				.withQueryParam("page", WireMock.equalTo("2"))
				.willReturn(WireMock.aResponse().withStatus(200)
						.withHeader("Content-Type", "application/json")
						.withBody(new JSONObject()
								.put("values", new JSONArray()
										.put(commentJson(3, "gone", "b.yml", 4, true))
										.put(commentJson(4, "file-level", "c.yml", null, false)))
								.toString())));

		List<PullRequestComment> comments = new BBCloudApi(entity).listComments(mockPr);

		Assertions.assertEquals(List.of(new PullRequestComment(1, "summary", null, null),
				new PullRequestComment(2, "inline", "a.yml", 12),
				new PullRequestComment(4, "file-level", "c.yml", null)), comments);
	}

	@Test
	public void testListCommentsDoNothingMakesNoCall() {
		BDDMockito.when(entity.getRejectOption()).thenReturn(BBCloudRejectOption.DO_NOTHING);

		Assertions.assertEquals(List.of(), new BBCloudApi(entity).listComments(mockPr));
		WireMock.verify(0, WireMock.getRequestedFor(WireMock.anyUrl()));
	}

	@Test
	public void testListCommentsFailureReturnsNull() {
		givenCommentingIntegration();
		WireMock.stubFor(WireMock.get(WireMock.urlPathEqualTo(buildRequestUrl(prBase, "comments")))
				.willReturn(WireMock.aResponse().withStatus(500)));

		Assertions.assertNull(new BBCloudApi(entity).listComments(mockPr));
	}

	@Test
	public void testSendInlineCommentPostsPathAndLine() {
		givenCommentingIntegration();
		WireMock.stubFor(WireMock.post(buildRequestUrl(prBase, "comments"))
				.willReturn(WireMock.aResponse().withStatus(201)));

		Assertions.assertTrue(
				new BBCloudApi(entity).sendInlineComment(mockPr, "src/a.yml", 12, "text"));

		WireMock.verify(WireMock.postRequestedFor(
				WireMock.urlEqualTo(buildRequestUrl(prBase, "comments")))
				.withRequestBody(WireMock.equalToJson(
						"{\"content\":{\"raw\":\"text\"},\"inline\":{\"path\":\"src/a.yml\",\"to\":12}}")));
	}

	@Test
	public void testSendInlineCommentRejectedReturnsFalse() {
		givenCommentingIntegration();
		WireMock.stubFor(WireMock.post(buildRequestUrl(prBase, "comments"))
				.willReturn(WireMock.aResponse().withStatus(400)));

		Assertions.assertFalse(
				new BBCloudApi(entity).sendInlineComment(mockPr, "src/a.yml", 12, "text"));
	}

	@Test
	public void testUpdateCommentPutsNewText() {
		givenCommentingIntegration();
		WireMock.stubFor(WireMock.put(buildRequestUrl(prBase, "comments", "42"))
				.willReturn(WireMock.aResponse().withStatus(200)));

		Assertions.assertTrue(new BBCloudApi(entity).updateComment(mockPr, 42, "fixed"));

		WireMock.verify(WireMock.putRequestedFor(
				WireMock.urlEqualTo(buildRequestUrl(prBase, "comments", "42")))
				.withRequestBody(WireMock.equalToJson("{\"content\":{\"raw\":\"fixed\"}}")));
	}

	@Test
	public void testDeleteCommentDeletes() {
		givenCommentingIntegration();
		WireMock.stubFor(WireMock.delete(buildRequestUrl(prBase, "comments", "42"))
				.willReturn(WireMock.aResponse().withStatus(204)));

		Assertions.assertTrue(new BBCloudApi(entity).deleteComment(mockPr, 42));

		WireMock.verify(WireMock.deleteRequestedFor(
				WireMock.urlEqualTo(buildRequestUrl(prBase, "comments", "42"))));
	}

	@Test
	public void testDeleteCommentFailureReturnsFalse() {
		givenCommentingIntegration();
		WireMock.stubFor(WireMock.delete(buildRequestUrl(prBase, "comments", "42"))
				.willReturn(WireMock.aResponse().withStatus(403)));

		Assertions.assertFalse(new BBCloudApi(entity).deleteComment(mockPr, 42));
	}

	@Test
	public void testReplyToCommentPostsAReplyUnderIt() {
		givenCommentingIntegration();
		WireMock.stubFor(WireMock.post(buildRequestUrl(prBase, "comments"))
				.willReturn(WireMock.aResponse().withStatus(201)));

		Assertions.assertTrue(new BBCloudApi(entity).replyToComment(mockPr, 42, "noted"));

		WireMock.verify(WireMock.postRequestedFor(
				WireMock.urlEqualTo(buildRequestUrl(prBase, "comments")))
				.withRequestBody(WireMock.equalToJson(
						"{\"content\":{\"raw\":\"noted\"},\"parent\":{\"id\":42}}")));
	}

	@Test
	public void testOnlyBlockPrDeclinesBlockedPullRequests() {
		for (BBCloudRejectOption option : BBCloudRejectOption.values()) {
			BDDMockito.when(entity.getRejectOption()).thenReturn(option);
			Assertions.assertEquals(option != BBCloudRejectOption.BLOCK_PR,
					new BBCloudApi(entity).keepsBlockedPullRequestsOpen(), option.name());
		}
	}

	@Test
	public void testReplyToCommentRejectedReturnsFalse() {
		givenCommentingIntegration();
		WireMock.stubFor(WireMock.post(buildRequestUrl(prBase, "comments"))
				.willReturn(WireMock.aResponse().withStatus(404)));

		Assertions.assertFalse(new BBCloudApi(entity).replyToComment(mockPr, 42, "noted"));
	}

	@Test
	public void testInlineWritesDoNothingMakeNoCalls() {
		BDDMockito.when(entity.getRejectOption()).thenReturn(BBCloudRejectOption.DO_NOTHING);
		BBCloudApi api = new BBCloudApi(entity);

		Assertions.assertTrue(api.replyToComment(mockPr, 1, "text"));
		Assertions.assertTrue(api.sendInlineComment(mockPr, "a.yml", 1, "text"));
		Assertions.assertTrue(api.updateComment(mockPr, 1, "text"));
		Assertions.assertTrue(api.deleteComment(mockPr, 1));
		WireMock.verify(0, WireMock.anyRequestedFor(WireMock.anyUrl()));
	}

	@Test
	public void testUpdateCommentRetriesOnRateLimit() {
		givenCommentingIntegration();
		String url = buildRequestUrl(prBase, "comments", "42");
		WireMock.stubFor(WireMock.put(url)
				.willReturn(WireMock.aResponse().withStatus(429).withHeader("Retry-After", "0"))
				.inScenario("updateRateLimit").whenScenarioStateIs(Scenario.STARTED)
				.willSetStateTo("ok"));
		WireMock.stubFor(WireMock.put(url).willReturn(WireMock.aResponse().withStatus(200))
				.inScenario("updateRateLimit").whenScenarioStateIs("ok"));

		Assertions.assertTrue(new BBCloudApi(entity).updateComment(mockPr, 42, "fixed"));
		WireMock.verify(2, WireMock.putRequestedFor(WireMock.urlEqualTo(url)));
	}
    @Test
    void boundedProviderExcerptReadsExactCommitAndEnforcesByteLimit() throws Exception {
        String commit = "a".repeat(40), path = repoBase + "/src/" + commit + "/src/a.java";
        BDDMockito.when(entity.makeSourceFileUrl("repo", commit, "src/a.java")).thenReturn(apiBase + path);
        WireMock.stubFor(WireMock.get(path).willReturn(WireMock.aResponse().withStatus(200).withBody("exact pinned bytes")));
        var api = new BBCloudApi(entity);
        Assertions.assertArrayEquals("exact pinned bytes".getBytes(java.nio.charset.StandardCharsets.UTF_8), api.boundedFileAtCommit("repo", commit, "src/a.java", 64));
        Assertions.assertThrows(IOException.class, () -> api.boundedFileAtCommit("repo", commit, "src/a.java", 5));
    }

    @Test
    void providerSourceRefusesBranchesAndEncodedTraversalBeforeTransport() {
        var api = new BBCloudApi(entity);
        Assertions.assertThrows(IOException.class, () -> api.boundedFileAtCommit("repo", "main", "src/a.java", 64));
        for (String path : List.of("../a.java", "src/a.java?token=secret", "src/%2e%2e/a.java", "/a.java"))
            Assertions.assertThrows(IOException.class, () -> api.boundedFileAtCommit("repo", "a".repeat(40), path, 64));
        WireMock.verify(0, WireMock.anyRequestedFor(WireMock.anyUrl()));
    }

}
