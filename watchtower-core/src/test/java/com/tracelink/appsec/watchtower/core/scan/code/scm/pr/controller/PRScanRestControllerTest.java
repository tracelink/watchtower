package com.tracelink.appsec.watchtower.core.scan.code.scm.pr.controller;

import java.util.concurrent.RejectedExecutionException;

import org.hamcrest.Matchers;
import org.json.JSONObject;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.BDDMockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.http.MediaType;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.RequestPostProcessor;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;

import com.tracelink.appsec.watchtower.core.WatchtowerTestApplication;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.ApiIntegrationEntity;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.ApiIntegrationService;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.ApiType;
import com.tracelink.appsec.watchtower.core.scan.code.scm.api.bb.BBWebhookSignature;
import com.tracelink.appsec.watchtower.core.scan.code.scm.api.bb.BBCloudIntegrationEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.api.bb.BBPullRequest;
import com.tracelink.appsec.watchtower.core.scan.code.scm.bb.BBPullRequestTest;
import org.springframework.core.task.TaskRejectedException;
import com.tracelink.appsec.watchtower.core.exception.ScanQuiescedException;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.PRScanSubmitResult;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.PullRequest;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.PullRequestState;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.bypass.PRCommentCommandService;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.service.PRScanResultService;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.service.PRScanningService;

@ExtendWith(SpringExtension.class)
@SpringBootTest(classes = WatchtowerTestApplication.class)
@AutoConfigureMockMvc
public class PRScanRestControllerTest {
	private static final String WEBHOOK_SECRET = "test-webhook-secret";

	@Autowired
	private MockMvc mockMvc;

	@MockitoBean
	private PRScanningService mockScanService;

	@MockitoBean
	private PRScanResultService mockResultService;


	@MockitoBean
	private ApiIntegrationService mockApiService;

	@MockitoBean
	private PRCommentCommandService mockCommentService;

	private static String commentPayload(String text) throws Exception {
		JSONObject json = BBPullRequestTest.buildJSON();
		json.put("comment", new JSONObject().put("id", 99)
				.put("content", new JSONObject().put("raw", text)));
		json.put("actor", new JSONObject().put("display_name", "Dana Dev"));
		return json.toString();
	}

	private BBCloudIntegrationEntity configuredIntegration() {
		BBCloudIntegrationEntity integration = new BBCloudIntegrationEntity();
		integration.setWebhookSecret(WEBHOOK_SECRET);
		return integration;
	}

	private RequestPostProcessor validSignature() {
		return request -> {
			request.addHeader(BBWebhookSignature.HEADER_NAME,
					BBWebhookSignature.headerValueFor(WEBHOOK_SECRET,
							request.getContentAsByteArray()));
			return request;
		};
	}

	@Test
	public void testScanPRSuccess() throws Exception {
		BDDMockito.when(mockScanService.doPullRequestScan(BDDMockito.any()))
				.thenReturn(PRScanSubmitResult.QUEUED);
		ApiIntegrationEntity apiEntity = configuredIntegration();
		String prJSON = BBPullRequestTest.buildStandardJSONString();
		String apiLabel = "apiLabel";
		PullRequest pr = new PullRequest(apiLabel);
		pr.setState(PullRequestState.ACTIVE);
		BDDMockito.when(mockApiService.findByLabel(apiLabel)).thenReturn(apiEntity);

		mockMvc.perform(MockMvcRequestBuilders.post("/rest/scan/" + apiLabel)
				.with(validSignature())
				.contentType(MediaType.APPLICATION_JSON)
				.content(prJSON)).andExpect(MockMvcResultMatchers.status().is2xxSuccessful())
				.andExpect(MockMvcResultMatchers.content()
						.string(Matchers.is(PRScanSubmitResult.QUEUED.getDescription())));

		BDDMockito.verify(mockScanService).doPullRequestScan(BDDMockito.any(BBPullRequest.class));
	}

	@Test
	public void testScanPRFailure() throws Exception {
		String type = ApiType.BITBUCKET_CLOUD.getTypeName();
		BDDMockito.willThrow(RejectedExecutionException.class).given(mockScanService)
				.doPullRequestScan(BDDMockito.any());
		BDDMockito.when(mockApiService.findByLabel(type)).thenReturn(configuredIntegration());

		String prJSON = BBPullRequestTest.buildStandardJSONString();

		mockMvc.perform(MockMvcRequestBuilders.post("/rest/scan/" + type)
				.with(validSignature())
				.contentType(MediaType.APPLICATION_JSON)
				.content(prJSON)).andExpect(MockMvcResultMatchers.status().is4xxClientError())
				.andExpect(MockMvcResultMatchers.content()
						.string(Matchers.is("Unable to process scan request")));
	}

	@Test
	public void testResolveOnDeclinedPr() throws Exception {
		ApiIntegrationEntity apiEntity = configuredIntegration();
		JSONObject prJSON = BBPullRequestTest.buildJSON();
		prJSON.getJSONObject("pullrequest").put("state", "declined");
		String apiLabel = "apiLabel";
		PullRequest pr = new PullRequest(apiLabel);
		pr.setState(PullRequestState.DECLINED);
		BDDMockito.when(mockApiService.findByLabel(apiLabel)).thenReturn(apiEntity);

		mockMvc.perform(MockMvcRequestBuilders.post("/rest/scan/" + apiLabel)
				.with(validSignature())
				.contentType(MediaType.APPLICATION_JSON)
				.content(prJSON.toString()))
				.andExpect(MockMvcResultMatchers.status().is2xxSuccessful())
				.andExpect(MockMvcResultMatchers.content()
						.string(Matchers.containsString("PR already DECLINED")));

		BDDMockito.verify(mockScanService, BDDMockito.never()).doPullRequestScan(BDDMockito.any());
		BDDMockito.verify(mockResultService).markPrResolved(BDDMockito.any(BBPullRequest.class),
				BDDMockito.eq(false));
	}

	@Test
	public void aMergeWhileAScanIsPendingIsRecordedAsSuch() throws Exception {
		// The merge gate view counts this merge as "scan in progress"
		ApiIntegrationEntity apiEntity = configuredIntegration();
		JSONObject prJSON = BBPullRequestTest.buildJSON();
		prJSON.getJSONObject("pullrequest").put("state", "merged");
		BDDMockito.when(mockApiService.findByLabel("apiLabel")).thenReturn(apiEntity);
		BDDMockito.when(mockScanService.hasPendingScan(BDDMockito.any())).thenReturn(true);

		mockMvc.perform(MockMvcRequestBuilders.post("/rest/scan/apiLabel")
				.with(validSignature())
				.contentType(MediaType.APPLICATION_JSON)
				.content(prJSON.toString()))
				.andExpect(MockMvcResultMatchers.status().is2xxSuccessful());

		BDDMockito.verify(mockResultService).markPrResolved(BDDMockito.any(BBPullRequest.class),
				BDDMockito.eq(true));
	}

	@Test
	public void testResolveOnMergedPr() throws Exception {
		// A merged PR is finished: resolve it and do not spend a scan on it. Previously
		// only DECLINED was recognised, so a merged PR was scanned and left unresolved.
		ApiIntegrationEntity apiEntity = configuredIntegration();
		JSONObject prJSON = BBPullRequestTest.buildJSON();
		prJSON.getJSONObject("pullrequest").put("state", "merged");
		String apiLabel = "apiLabel";
		BDDMockito.when(mockApiService.findByLabel(apiLabel)).thenReturn(apiEntity);

		mockMvc.perform(MockMvcRequestBuilders.post("/rest/scan/" + apiLabel)
				.with(validSignature())
				.contentType(MediaType.APPLICATION_JSON)
				.content(prJSON.toString()))
				.andExpect(MockMvcResultMatchers.status().is2xxSuccessful())
				.andExpect(MockMvcResultMatchers.content()
						.string(Matchers.containsString("PR already MERGED")));

		BDDMockito.verify(mockScanService, BDDMockito.never()).doPullRequestScan(BDDMockito.any());
		BDDMockito.verify(mockResultService).markPrResolved(BDDMockito.any(BBPullRequest.class),
				BDDMockito.eq(false));
	}

	@Test
	public void testQueuedScanReturns202() throws Exception {
		ApiIntegrationEntity apiEntity = configuredIntegration();
		String apiLabel = "apiLabel";
		BDDMockito.when(mockApiService.findByLabel(apiLabel)).thenReturn(apiEntity);
		BDDMockito.when(mockScanService.doPullRequestScan(BDDMockito.any()))
				.thenReturn(PRScanSubmitResult.QUEUED);

		mockMvc.perform(MockMvcRequestBuilders.post("/rest/scan/" + apiLabel)
				.with(validSignature())
				.contentType(MediaType.APPLICATION_JSON)
				.content(BBPullRequestTest.buildStandardJSONString()))
				.andExpect(MockMvcResultMatchers.status().isAccepted());
	}

	@Test
	public void testDroppedScanReturns422() throws Exception {
		// The whole point of item 1.10: a dropped scan used to answer 200, so Bitbucket
		// logged the delivery as successful while nothing had been scanned.
		ApiIntegrationEntity apiEntity = configuredIntegration();
		String apiLabel = "apiLabel";
		BDDMockito.when(mockApiService.findByLabel(apiLabel)).thenReturn(apiEntity);
		BDDMockito.when(mockScanService.doPullRequestScan(BDDMockito.any()))
				.thenReturn(PRScanSubmitResult.NO_RULESET);

		mockMvc.perform(MockMvcRequestBuilders.post("/rest/scan/" + apiLabel)
				.with(validSignature())
				.contentType(MediaType.APPLICATION_JSON)
				.content(BBPullRequestTest.buildStandardJSONString()))
				.andExpect(MockMvcResultMatchers.status().isUnprocessableEntity())
				.andExpect(MockMvcResultMatchers.content()
						.string(Matchers.containsString("not configured with a ruleset")));
	}

	@Test
	public void testQuiescedSystemReturns503() throws Exception {
		// Retryable, unlike a misconfiguration, so it must not be a 4xx.
		ApiIntegrationEntity apiEntity = configuredIntegration();
		String apiLabel = "apiLabel";
		BDDMockito.when(mockApiService.findByLabel(apiLabel)).thenReturn(apiEntity);
		BDDMockito.when(mockScanService.doPullRequestScan(BDDMockito.any()))
				.thenThrow(new ScanQuiescedException("Quiesced. Did not schedule PR: pr"));

		mockMvc.perform(MockMvcRequestBuilders.post("/rest/scan/" + apiLabel)
				.with(validSignature())
				.contentType(MediaType.APPLICATION_JSON)
				.content(BBPullRequestTest.buildStandardJSONString()))
				.andExpect(MockMvcResultMatchers.status().isServiceUnavailable());
	}

	@Test
	public void testFullQueueReturns503() throws Exception {
		ApiIntegrationEntity apiEntity = configuredIntegration();
		String apiLabel = "apiLabel";
		BDDMockito.when(mockApiService.findByLabel(apiLabel)).thenReturn(apiEntity);
		BDDMockito.when(mockScanService.doPullRequestScan(BDDMockito.any()))
				.thenThrow(new TaskRejectedException("queue full"));

		mockMvc.perform(MockMvcRequestBuilders.post("/rest/scan/" + apiLabel)
				.with(validSignature())
				.contentType(MediaType.APPLICATION_JSON)
				.content(BBPullRequestTest.buildStandardJSONString()))
				.andExpect(MockMvcResultMatchers.status().isServiceUnavailable())
				.andExpect(MockMvcResultMatchers.content()
						.string(Matchers.containsString("queue is full")));
	}

	@Test
	public void testValidSignatureIsProcessed() throws Exception {
		BBCloudIntegrationEntity apiEntity = new BBCloudIntegrationEntity();
		apiEntity.setWebhookSecret("s3cr3t");
		String apiLabel = "apiLabel";
		String prJSON = BBPullRequestTest.buildStandardJSONString();
		BDDMockito.when(mockApiService.findByLabel(apiLabel)).thenReturn(apiEntity);
		BDDMockito.when(mockScanService.doPullRequestScan(BDDMockito.any()))
				.thenReturn(PRScanSubmitResult.QUEUED);

		mockMvc.perform(MockMvcRequestBuilders.post("/rest/scan/" + apiLabel)
				.header("X-Hub-Signature",
						BBWebhookSignature.headerValueFor("s3cr3t",
						prJSON.getBytes(java.nio.charset.StandardCharsets.UTF_8)))
				.contentType(MediaType.APPLICATION_JSON)
				.content(prJSON))
				.andExpect(MockMvcResultMatchers.status().isAccepted());
	}

	@Test
	public void testWrongSignatureIsRejectedWith401() throws Exception {
		// This endpoint is permitAll(), so the signature is the only thing separating a
		// genuine Bitbucket delivery from any client that can reach the pod.
		BBCloudIntegrationEntity apiEntity = new BBCloudIntegrationEntity();
		apiEntity.setWebhookSecret("s3cr3t");
		String apiLabel = "apiLabel";
		BDDMockito.when(mockApiService.findByLabel(apiLabel)).thenReturn(apiEntity);

		mockMvc.perform(MockMvcRequestBuilders.post("/rest/scan/" + apiLabel)
				.header("X-Hub-Signature", "sha256=deadbeef")
				.contentType(MediaType.APPLICATION_JSON)
				.content(BBPullRequestTest.buildStandardJSONString()))
				.andExpect(MockMvcResultMatchers.status().isUnauthorized());

		BDDMockito.verify(mockScanService, BDDMockito.never()).doPullRequestScan(BDDMockito.any());
	}

	@Test
	public void testMissingSignatureIsRejectedWhenASecretIsConfigured() throws Exception {
		BBCloudIntegrationEntity apiEntity = new BBCloudIntegrationEntity();
		apiEntity.setWebhookSecret("s3cr3t");
		String apiLabel = "apiLabel";
		BDDMockito.when(mockApiService.findByLabel(apiLabel)).thenReturn(apiEntity);

		mockMvc.perform(MockMvcRequestBuilders.post("/rest/scan/" + apiLabel)
				.contentType(MediaType.APPLICATION_JSON)
				.content(BBPullRequestTest.buildStandardJSONString()))
				.andExpect(MockMvcResultMatchers.status().isUnauthorized());
	}

	@Test
	public void testWebhookIsRejectedWhenNoSecretIsConfigured() throws Exception {
		BBCloudIntegrationEntity apiEntity = new BBCloudIntegrationEntity();
		String apiLabel = "apiLabel";
		BDDMockito.when(mockApiService.findByLabel(apiLabel)).thenReturn(apiEntity);
		mockMvc.perform(MockMvcRequestBuilders.post("/rest/scan/" + apiLabel)
				.contentType(MediaType.APPLICATION_JSON)
				.content(BBPullRequestTest.buildStandardJSONString()))
				.andExpect(MockMvcResultMatchers.status().isUnauthorized());

		BDDMockito.verifyNoInteractions(mockScanService);
	}

	@Test
	public void testFulfilledEventResolvesWithoutScanning() throws Exception {
		// Handling this event resolves a merged PR within seconds, instead of waiting up
		// to three hours for the synchronizer to notice.
		ApiIntegrationEntity apiEntity = configuredIntegration();
		String apiLabel = "apiLabel";
		BDDMockito.when(mockApiService.findByLabel(apiLabel)).thenReturn(apiEntity);

		mockMvc.perform(MockMvcRequestBuilders.post("/rest/scan/" + apiLabel)
				.with(validSignature())
				.header("X-Event-Key", "pullrequest:fulfilled")
				.contentType(MediaType.APPLICATION_JSON)
				.content(BBPullRequestTest.buildStandardJSONString()))
				.andExpect(MockMvcResultMatchers.status().is2xxSuccessful());

		BDDMockito.verify(mockResultService).markPrResolved(BDDMockito.any(BBPullRequest.class),
				BDDMockito.eq(false));
		BDDMockito.verify(mockScanService, BDDMockito.never()).doPullRequestScan(BDDMockito.any());
	}

	@Test
	public void testRejectedEventResolvesWithoutScanning() throws Exception {
		ApiIntegrationEntity apiEntity = configuredIntegration();
		String apiLabel = "apiLabel";
		BDDMockito.when(mockApiService.findByLabel(apiLabel)).thenReturn(apiEntity);

		mockMvc.perform(MockMvcRequestBuilders.post("/rest/scan/" + apiLabel)
				.with(validSignature())
				.header("X-Event-Key", "pullrequest:rejected")
				.contentType(MediaType.APPLICATION_JSON)
				.content(BBPullRequestTest.buildStandardJSONString()))
				.andExpect(MockMvcResultMatchers.status().is2xxSuccessful());

		BDDMockito.verify(mockResultService).markPrResolved(BDDMockito.any(BBPullRequest.class),
				BDDMockito.eq(false));
		BDDMockito.verify(mockScanService, BDDMockito.never()).doPullRequestScan(BDDMockito.any());
	}

	@Test
	public void testUpdatedEventTriggersAScan() throws Exception {
		ApiIntegrationEntity apiEntity = configuredIntegration();
		String apiLabel = "apiLabel";
		BDDMockito.when(mockApiService.findByLabel(apiLabel)).thenReturn(apiEntity);
		BDDMockito.when(mockScanService.doPullRequestScan(BDDMockito.any()))
				.thenReturn(PRScanSubmitResult.QUEUED);

		mockMvc.perform(MockMvcRequestBuilders.post("/rest/scan/" + apiLabel)
				.with(validSignature())
				.header("X-Event-Key", "pullrequest:updated")
				.contentType(MediaType.APPLICATION_JSON)
				.content(BBPullRequestTest.buildStandardJSONString()))
				.andExpect(MockMvcResultMatchers.status().isAccepted());

		BDDMockito.verify(mockScanService).doPullRequestScan(BDDMockito.any());
	}

	@Test
	public void testIgnoredEventIsNotEchoedBack() throws Exception {
		// The event header is caller-controlled; echoing it into a response a browser might
		// render as HTML was a reflected-XSS vector (Snyk java/XSS).
		ApiIntegrationEntity apiEntity = configuredIntegration();
		BDDMockito.when(mockApiService.findByLabel("apiLabel")).thenReturn(apiEntity);

		mockMvc.perform(MockMvcRequestBuilders.post("/rest/scan/apiLabel")
				.with(validSignature())
				.header("X-Event-Key", "<script>alert(1)</script>")
				.accept(MediaType.TEXT_HTML)
				.contentType(MediaType.APPLICATION_JSON)
				.content(BBPullRequestTest.buildStandardJSONString()))
				.andExpect(MockMvcResultMatchers.status().isOk())
				.andExpect(MockMvcResultMatchers.content()
						.string(Matchers.not(Matchers.containsString("<script>"))))
				.andExpect(MockMvcResultMatchers.content()
						.contentTypeCompatibleWith(MediaType.TEXT_PLAIN));
	}

	@Test
	public void testCommentCommandGoesToTheCommandServiceNotTheScanner() throws Exception {
		ApiIntegrationEntity apiEntity = configuredIntegration();
		String apiLabel = "apiLabel";
		BDDMockito.when(mockApiService.findByLabel(apiLabel)).thenReturn(apiEntity);
		BDDMockito.when(mockCommentService.submit(BDDMockito.any(), BDDMockito.anyString()))
				.thenReturn(true);

		mockMvc.perform(MockMvcRequestBuilders.post("/rest/scan/" + apiLabel)
				.with(validSignature())
				.header("X-Event-Key", "pullrequest:comment_created")
				.contentType(MediaType.APPLICATION_JSON)
				.content(commentPayload("/watchtower bypass Test fixture")))
				.andExpect(MockMvcResultMatchers.status().isAccepted());

		BDDMockito.verify(mockCommentService).submit(
				BDDMockito.argThat(
						pr -> String.valueOf(BBPullRequestTest.prId).equals(pr.getPrId())),
				BDDMockito.contains("/watchtower bypass"));
		BDDMockito.verifyNoInteractions(mockScanService);
		BDDMockito.verify(mockResultService, BDDMockito.never()).markPrResolved(BDDMockito.any(),
				BDDMockito.anyBoolean());
	}

	@Test
	public void testOrdinaryCommentIsAcknowledgedWithoutAnyWork() throws Exception {
		ApiIntegrationEntity apiEntity = configuredIntegration();
		String apiLabel = "apiLabel";
		BDDMockito.when(mockApiService.findByLabel(apiLabel)).thenReturn(apiEntity);

		mockMvc.perform(MockMvcRequestBuilders.post("/rest/scan/" + apiLabel)
				.with(validSignature())
				.header("X-Event-Key", "pullrequest:comment_created")
				.contentType(MediaType.APPLICATION_JSON)
				.content(commentPayload("Looks good to me")))
				.andExpect(MockMvcResultMatchers.status().isOk());

		BDDMockito.verifyNoInteractions(mockScanService, mockResultService, mockCommentService);
	}

	@Test
	public void testUnsignedCommentIsRejected() throws Exception {
		ApiIntegrationEntity apiEntity = configuredIntegration();
		String apiLabel = "apiLabel";
		BDDMockito.when(mockApiService.findByLabel(apiLabel)).thenReturn(apiEntity);

		mockMvc.perform(MockMvcRequestBuilders.post("/rest/scan/" + apiLabel)
				.header("X-Event-Key", "pullrequest:comment_created")
				.contentType(MediaType.APPLICATION_JSON)
				.content(commentPayload("/watchtower bypass Test fixture")))
				.andExpect(MockMvcResultMatchers.status().isUnauthorized());

		BDDMockito.verifyNoInteractions(mockCommentService);
	}

	@Test
	public void testUninterestingEventIsIgnoredWithoutScanning() throws Exception {
		// Subscribing the hook to an approval event must not queue a scan.
		ApiIntegrationEntity apiEntity = configuredIntegration();
		String apiLabel = "apiLabel";
		BDDMockito.when(mockApiService.findByLabel(apiLabel)).thenReturn(apiEntity);

		mockMvc.perform(MockMvcRequestBuilders.post("/rest/scan/" + apiLabel)
				.with(validSignature())
				.header("X-Event-Key", "pullrequest:approved")
				.contentType(MediaType.APPLICATION_JSON)
				.content(BBPullRequestTest.buildStandardJSONString()))
				.andExpect(MockMvcResultMatchers.status().isOk())
				.andExpect(MockMvcResultMatchers.content()
						.string(Matchers.containsString("needs no scan")));

		BDDMockito.verify(mockScanService, BDDMockito.never()).doPullRequestScan(BDDMockito.any());
		BDDMockito.verifyNoInteractions(mockResultService);
	}

	@Test
	public void testMissingEventKeyKeepsTheStateBasedBehaviour() throws Exception {
		// Automation callers that are not Bitbucket do not send the header, and must keep
		// working exactly as before.
		ApiIntegrationEntity apiEntity = configuredIntegration();
		String apiLabel = "apiLabel";
		BDDMockito.when(mockApiService.findByLabel(apiLabel)).thenReturn(apiEntity);
		BDDMockito.when(mockScanService.doPullRequestScan(BDDMockito.any()))
				.thenReturn(PRScanSubmitResult.QUEUED);

		mockMvc.perform(MockMvcRequestBuilders.post("/rest/scan/" + apiLabel)
				.with(validSignature())
				.contentType(MediaType.APPLICATION_JSON)
				.content(BBPullRequestTest.buildStandardJSONString()))
				.andExpect(MockMvcResultMatchers.status().isAccepted());

		BDDMockito.verify(mockScanService).doPullRequestScan(BDDMockito.any());
	}
}
