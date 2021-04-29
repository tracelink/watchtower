package com.tracelink.appsec.watchtower.core.scan.scm.pr.controller;

import javax.servlet.http.HttpServletRequest;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.tracelink.appsec.watchtower.core.exception.ScanRejectedException;
import com.tracelink.appsec.watchtower.core.scan.scm.ScmFactoryService;
import com.tracelink.appsec.watchtower.core.scan.scm.apiintegration.APIIntegrationEntity;
import com.tracelink.appsec.watchtower.core.scan.scm.apiintegration.APIIntegrationService;
import com.tracelink.appsec.watchtower.core.scan.scm.pr.PullRequest;
import com.tracelink.appsec.watchtower.core.scan.scm.pr.PullRequestState;
import com.tracelink.appsec.watchtower.core.scan.scm.pr.service.PRScanResultService;
import com.tracelink.appsec.watchtower.core.scan.scm.pr.service.PRScanningService;

/**
 * Controller for all REST API calls. Handles sending a scan via REST webhook.
 *
 * @author csmith
 */
@RestController
@PreAuthorize("permitAll()")
public class PRScanRestController {
	private static final Logger LOG = LoggerFactory.getLogger(PRScanRestController.class);

	private PRScanningService scanService;

	private PRScanResultService prResultService;

	private ScmFactoryService scmFactory;

	private APIIntegrationService apiService;

	public PRScanRestController(@Autowired PRScanningService scanService,
			@Autowired PRScanResultService prResultService,
			@Autowired ScmFactoryService scmFactory,
			@Autowired APIIntegrationService apiService) {
		this.scanService = scanService;
		this.prResultService = prResultService;
		this.scmFactory = scmFactory;
		this.apiService = apiService;
	}

	@PostMapping("/rest/scan/{source}")
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

			PullRequest pr = scmFactory.createPrFromAutomation(apiEntity, pullRequest);
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
}
