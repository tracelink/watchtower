package com.tracelink.appsec.watchtower.core.scan.scm.bb;

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

import com.github.tomakehurst.wiremock.client.WireMock;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import com.github.tomakehurst.wiremock.http.Fault;
import com.github.tomakehurst.wiremock.stubbing.Scenario;
import com.tracelink.appsec.watchtower.core.WireMockExtension;
import com.tracelink.appsec.watchtower.core.exception.ScanRejectedException;
import com.tracelink.appsec.watchtower.core.logging.CoreLogWatchExtension;
import com.tracelink.appsec.watchtower.core.report.ScanReport;
import com.tracelink.appsec.watchtower.core.scan.scm.api.ApiIntegrationException;
import com.tracelink.appsec.watchtower.core.scan.scm.api.bb.BBCloudApi;
import com.tracelink.appsec.watchtower.core.scan.scm.api.bb.BBCloudIntegrationEntity;
import com.tracelink.appsec.watchtower.core.scan.scm.pr.PullRequest;
import com.tracelink.appsec.watchtower.core.scan.scm.pr.data.DiffFile;

@ExtendWith(MockitoExtension.class)
public class BBCloudApiTest {

	@RegisterExtension
	public WireMockExtension wireMockExtension =
			new WireMockExtension(WireMockConfiguration.wireMockConfig().dynamicPort());

	@Mock
	private PullRequest mockPr;

	@Mock
	private ScanReport mockReport;

	@RegisterExtension
	public CoreLogWatchExtension logWatcher = CoreLogWatchExtension.forClass(BBCloudApi.class);

	private String apiBase;
	private String repoBase;
	private String prBase;
	private String workspaceUrl;

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

		BBCloudApi api = new BBCloudApi(entity);
		api.sendComment(mockPr, message);
		WireMock.verify(
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

		BBCloudApi api = new BBCloudApi(entity);
		api.blockPR(mockPr);
		WireMock.verify(
				WireMock.postRequestedFor(WireMock.urlEqualTo(buildRequestUrl(prBase, "decline"))));
	}

	@Test
	public void testBlockPRRateLimit() {
		BDDMockito.when(entity.makeApiPRUrl(BDDMockito.anyString(), BDDMockito.anyString()))
				.thenReturn(apiBase + prBase);
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

		BBCloudApi api = new BBCloudApi(entity);
		api.blockPR(mockPr);
		WireMock.verify(
				WireMock.postRequestedFor(WireMock.urlEqualTo(buildRequestUrl(prBase, "decline"))));
		Assertions.assertTrue(
				logWatcher.getMessages().get(0).contains("Exception while declining PR"));
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
}
