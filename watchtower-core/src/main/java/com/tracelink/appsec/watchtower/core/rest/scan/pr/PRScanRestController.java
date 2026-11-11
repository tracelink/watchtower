package com.tracelink.appsec.watchtower.core.rest.scan.pr;

import com.tracelink.appsec.watchtower.core.exception.ScanQuiescedException;
import com.tracelink.appsec.watchtower.core.exception.ScanRejectedException;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.ApiIntegrationEntity;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.ApiIntegrationException;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.ApiIntegrationService;
import org.apache.commons.lang3.StringUtils;
import org.springframework.web.bind.annotation.RequestHeader;
import com.tracelink.appsec.watchtower.core.scan.code.scm.api.bb.BBCloudIntegrationEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.api.bb.BBWebhookSignature;
import com.tracelink.appsec.watchtower.core.scan.code.scm.api.bb.BBPullRequest;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.PRScanSubmitResult;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.PullRequest;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.bypass.PRCommentCommand;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.bypass.PRCommentCommandService;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.service.PRScanResultService;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.service.PRScanningService;
import java.nio.charset.StandardCharsets;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.task.TaskRejectedException;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Controller for all REST API calls. Handles sending a scan via REST webhook.
 *
 * @author csmith
 */
@RestController
@RequestMapping("/rest/scan")
@PreAuthorize("permitAll()")
public class PRScanRestController {

	private static final Logger LOG = LoggerFactory.getLogger(PRScanRestController.class);

	private PRScanningService scanService;

	private PRScanResultService prResultService;

	private ApiIntegrationService apiService;

	/**
	 * Bitbucket events that mean the Pull Request has new code to look at.
	 */
	private static final Set<String> SCAN_EVENTS =
			Set.of("pullrequest:created", "pullrequest:updated");

	/**
	 * Bitbucket events that mean the Pull Request is closed. Handling these resolves it
	 * within seconds instead of waiting for the next synchronizer pass, which is what
	 * makes the synchronizer a safety net rather than the primary mechanism.
	 */
	private static final Set<String> RESOLVE_EVENTS =
			Set.of("pullrequest:fulfilled", "pullrequest:rejected");

	/**
	 * A new comment, which may be a "/watchtower bypass &lt;reason&gt;" command (§4.18). It never
	 * reaches the scanner: ordinary comments are acknowledged after a substring check, and
	 * commands are handed to {@link PRCommentCommandService}'s own thread.
	 */
	private static final String COMMENT_EVENT = "pullrequest:comment_created";

	private final PRCommentCommandService commentService;

	public PRScanRestController(@Autowired PRScanningService scanService,
			@Autowired PRScanResultService prResultService,
			@Autowired ApiIntegrationService apiService,
			@Autowired PRCommentCommandService commentService) {
		this.commentService = commentService;
		this.scanService = scanService;
		this.prResultService = prResultService;
		this.apiService = apiService;
	}

	@PostMapping("/{source}")
	ResponseEntity<String> scanPullRequest(@PathVariable String source,
			@RequestHeader(value = BBWebhookSignature.HEADER_NAME,
					required = false) String signature,
			@RequestHeader(value = "X-Event-Key", required = false) String eventKey,
			@RequestBody byte[] rawBody) {
		// Raw bytes, not @RequestBody String. The SCM signs the bytes it sent, and
		// letting Spring decode to a String and re-encoding it for the digest breaks
		// verification for any payload containing a non-ASCII character - an accented
		// author name, a curly quote in a PR title - because the round-trip is only
		// byte-identical when the request charset happens to match.
		String pullRequest = new String(rawBody, StandardCharsets.UTF_8);
		String responseMessage;
		try {
			ApiIntegrationEntity apiEntity = apiService.findByLabel(source);
			if (apiEntity == null) {
				LOG.error("Unsupported api label: " + source);
				throw new ScanRejectedException("Unknown api label");
			}

			// This endpoint is permitAll() - Bitbucket cannot authenticate to it - so the
			// HMAC signature is the only thing distinguishing a real delivery from any
			// client that can reach the pod. Checked before the payload is parsed.
			if (!isSignatureAcceptable(apiEntity, source, signature, rawBody)) {
				return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
						.body("Invalid webhook signature");
			}

			if (COMMENT_EVENT.equals(eventKey)) {
				return handleComment(apiEntity, pullRequest);
			}

			PullRequest pr = createPrFromAutomation(apiEntity, pullRequest);

			// Act on what Bitbucket says happened, rather than treating every delivery as
			// a possible scan. Without this, subscribing the hook to anything else - a
			// comment, an approval - would queue a scan for it.
			//
			// The header is absent for callers that are not Bitbucket (the javadoc below
			// notes this endpoint also serves "some automation"), so no header means fall
			// through to the state-based decision that follows, which is the behaviour
			// those callers already rely on.
			// Guard the null before contains(): Set.of() is null-hostile and throws from
			// contains(null), which would turn every header-less request into a 400.
			boolean isScanEvent = eventKey != null && SCAN_EVENTS.contains(eventKey);
			boolean isResolveEvent = eventKey != null && RESOLVE_EVENTS.contains(eventKey);

			if (StringUtils.isNotBlank(eventKey) && !isScanEvent && !isResolveEvent) {
				LOG.debug("Ignoring Bitbucket event " + eventKey + " for api label " + source);
				// The header is not echoed: it is caller-controlled, and a body a browser
				// might render as HTML must not carry it (reflected XSS).
				return ResponseEntity.ok().contentType(MediaType.TEXT_PLAIN)
						.body("This event needs no scan");
			}

			if (isResolveEvent || pr.getState().isResolved()) {
				prResultService.markPrResolved(pr, scanService.hasPendingScan(pr));
				LOG.info("Pull Request " + pr.getPRString() + " is already " + pr.getState()
						+ "; resolved without scanning"
						+ (StringUtils.isBlank(eventKey) ? "" : " (event " + eventKey + ")"));
				responseMessage = "Scan Complete. PR already " + pr.getState();
			} else {
				// A dropped scan used to return 200, so Bitbucket recorded the delivery
				// as successful while nothing had been scanned. Each outcome now gets a
				// status that says what happened.
				PRScanSubmitResult result = scanService.doPullRequestScan(pr);
				HttpStatus status = switch (result) {
					case QUEUED -> HttpStatus.ACCEPTED;
					case DEDUPLICATED, ALREADY_RESOLVED, PAUSED -> HttpStatus.OK;
					case NO_RULESET, NO_SCANNERS -> HttpStatus.UNPROCESSABLE_ENTITY;
				};
				return ResponseEntity.status(status).body(result.getDescription());
			}
		} catch (ScanQuiescedException e) {
			// Temporary and operator-controlled, so tell the caller to retry rather than
			// reporting the request as invalid.
			return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE)
					.body("Scanning is temporarily unavailable. Retry later.");
		} catch (TaskRejectedException e) {
			LOG.warn("Scan queue is full; rejected webhook for " + source);
			return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE)
					.body("Scan queue is full. Retry later.");
		} catch (ScanRejectedException e) {
			// Understood but unactionable - a stale api label, or a misconfigured repo.
			LOG.warn("Rejected webhook for api label {}: {}", source, e.getMessage());
			return ResponseEntity.unprocessableEntity().body("Scan request was rejected");
		} catch (Exception e) {
			LOG.error("Error adding the scan", e);
			return ResponseEntity.badRequest().body("Unable to process scan request");
		}

		return ResponseEntity.ok(responseMessage);
	}

	/**
	 * A signed comment delivery. Most comments are not commands and stop at the substring check,
	 * before any parsing; a possible command is queued and answered 202.
	 */
	private ResponseEntity<String> handleComment(ApiIntegrationEntity apiEntity, String body)
			throws ApiIntegrationException {
		if (!PRCommentCommand.mayContainCommand(body)) {
			return ResponseEntity.ok().contentType(MediaType.TEXT_PLAIN).body("No command");
		}
		PullRequest pr = createPrFromAutomation(apiEntity, body);
		boolean queued = commentService.submit(pr, body);
		return ResponseEntity.status(queued ? HttpStatus.ACCEPTED : HttpStatus.OK)
				.contentType(MediaType.TEXT_PLAIN)
				.body(queued ? "Command queued" : "No command");
	}


	/**
	 * Decides whether a delivery may be processed, given its signature.
	 * <p>
	 * Webhooks fail closed: only Bitbucket Cloud integrations with a configured secret and
	 * a valid signature are accepted.
	 * <p>
	 * The signature scheme itself belongs to the integration - see
	 * {@link BBCloudIntegrationEntity#isWebhookSignatureValid(byte[], String)} - so this
	 * method only interprets the outcome.
	 *
	 * @param apiEntity   the integration the webhook arrived for
	 * @param source      the api label, for logging
	 * @param signature   the signature header value, may be null
	 * @param rawBody     the raw request body bytes
	 * @return true if the request should be processed
	 */
	private boolean isSignatureAcceptable(ApiIntegrationEntity apiEntity, String source,
			String signature, byte[] rawBody) {
		if (!(apiEntity instanceof BBCloudIntegrationEntity bbEntity)) {
			LOG.warn("Rejecting webhook for unsupported integration type and api label {}", source);
			return false;
		}
		if (!bbEntity.requiresSignedWebhooks()) {
			LOG.warn("Rejecting webhook for api label {} because no webhook secret is configured",
					source);
			return false;
		}
		if (bbEntity.isWebhookSignatureValid(rawBody, signature)) {
			LOG.debug(BBWebhookSignature.HEADER_NAME + " verified for api label " + source);
			return true;
		}
		// Distinguish the two failures. No header means the SCM is not sending one -
		// secret not set on its side - while a mismatch means the secrets differ or the
		// body was altered. Reporting them as one message hides the difference.
		if (StringUtils.isBlank(signature)) {
			LOG.warn("Rejecting webhook for api label {} because it has no {} header", source,
					BBWebhookSignature.HEADER_NAME);
			return false;
		}
		LOG.warn("Rejecting webhook for api label " + source + ": "
				+ BBWebhookSignature.HEADER_NAME
				+ " was present but does not match the payload. If this persists, confirm"
				+ " the secret is identical on both sides (whitespace included) and that"
				+ " nothing between Bitbucket and this service is altering the request body.");
		return false;
	}

	/**
	 * Given an ApiType and string representation of a pull request (usually from some automation),
	 * generate a pull request for the API type
	 *
	 * @param apiEntity   the Api entity descriptor for this PR
	 * @param pullRequest the string representation of a pull request used to generate the PR
	 * @return a PullRequest from the string data for this API
	 * @throws ApiIntegrationException if the api entity is null or the api type is unknown
	 */
	private PullRequest createPrFromAutomation(ApiIntegrationEntity apiEntity, String pullRequest)
			throws ApiIntegrationException {
		switch (apiEntity.getApiType()) {
			case BITBUCKET_CLOUD:
				BBPullRequest bbpr = new BBPullRequest(apiEntity.getApiLabel());
				bbpr.populateFromRequest(pullRequest);
				return bbpr;
			default:
				throw new ApiIntegrationException("No SCM API for this label.");
		}
	}
}
