package com.tracelink.appsec.watchtower.core.rest.scan.pr;

import javax.servlet.http.HttpServletRequest;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.tracelink.appsec.watchtower.core.exception.ScanRejectedException;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.APIIntegrationEntity;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.APIIntegrationService;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.ApiIntegrationException;
import com.tracelink.appsec.watchtower.core.scan.code.scm.bb.BBPullRequest;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.PullRequest;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.PullRequestState;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.service.PRScanResultService;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.service.PRScanningService;

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

	private APIIntegrationService apiService;

	public PRScanRestController(@Autowired PRScanningService scanService,
			@Autowired PRScanResultService prResultService,
			@Autowired APIIntegrationService apiService) {
		this.scanService = scanService;
		this.prResultService = prResultService;
		this.apiService = apiService;
	}

	@PostMapping("/{source}")
	ResponseEntity<String> scanPullRequest(@PathVariable String source,
			@RequestBody String pullRequest,
			HttpServletRequest request) {
		String responseMessage;
		try {
			APIIntegrationEntity apiEntity = apiService.findByLabel(source);
			if (apiEntity == null) {
				LOG.error("Unsupported api label: " + source);
				throw new ScanRejectedException("Unknown api label");
			}

			PullRequest pr = createPrFromAutomation(apiEntity, pullRequest);
			if (pr.getState().equals(PullRequestState.DECLINED)) {
				prResultService.markPrResolved(pr);
				responseMessage = "Scan Complete. PR already declined";
			} else {
				scanService.doPullRequestScan(pr);
				responseMessage = "Added scan successfully";
			}
		} catch (ScanRejectedException e) {
			return ResponseEntity.badRequest().body(e.getMessage());
		} catch (Exception e) {
			LOG.error("Error adding the scan", e);
			return ResponseEntity.badRequest().body("Error adding the scan: " + e.getMessage());
		}

		return ResponseEntity.ok(responseMessage);
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
	private PullRequest createPrFromAutomation(APIIntegrationEntity apiEntity, String pullRequest)
			throws ApiIntegrationException {
		if (apiEntity == null) {
			throw new ApiIntegrationException("Entity is null");
		}
		switch (apiEntity.getApiType()) {
			case BITBUCKET_CLOUD:
				BBPullRequest bbpr = new BBPullRequest(apiEntity.getApiLabel());
				bbpr.parseJsonFromWebhook(pullRequest);
				return bbpr;
			default:
				throw new ApiIntegrationException("No SCM API for this label.");
		}
	}
}
