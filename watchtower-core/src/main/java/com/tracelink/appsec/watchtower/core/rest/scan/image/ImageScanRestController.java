package com.tracelink.appsec.watchtower.core.rest.scan.image;

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
import com.tracelink.appsec.watchtower.core.scan.image.ImageScan;
import com.tracelink.appsec.watchtower.core.scan.image.api.ecr.EcrImageScan;
import com.tracelink.appsec.watchtower.core.scan.image.service.ImageScanningService;

@RestController
@RequestMapping("/rest/imagescan")
@PreAuthorize("permitAll()")
public class ImageScanRestController {
	private static final Logger LOG = LoggerFactory.getLogger(ImageScanRestController.class);
	private ImageScanningService scanService;

	private APIIntegrationService apiService;

	public ImageScanRestController(@Autowired ImageScanningService scanService,
			@Autowired APIIntegrationService apiService) {
		this.scanService = scanService;
		this.apiService = apiService;
	}

	@PostMapping("/{source}")
	ResponseEntity<String> scanPullRequest(@PathVariable String source,
			@RequestBody String imageScan,
			HttpServletRequest request) {
		String responseMessage;
		try {
			APIIntegrationEntity apiEntity = apiService.findByLabel(source);
			if (apiEntity == null) {
				LOG.error("Unsupported api label: " + source);
				throw new ScanRejectedException("Unknown api label");
			}

			ImageScan scan = createImageScanFromAutomation(apiEntity, imageScan);
			scanService.doImageScan(scan);
			responseMessage = "Added scan successfully";
		} catch (ScanRejectedException e) {
			return ResponseEntity.badRequest().body(e.getMessage());
		} catch (Exception e) {
			LOG.error("Error adding the scan", e);
			return ResponseEntity.badRequest().body("Error adding the scan: " + e.getMessage());
		}

		return ResponseEntity.ok(responseMessage);
	}

	private ImageScan createImageScanFromAutomation(APIIntegrationEntity apiEntity,
			String imageScan) throws ApiIntegrationException {
		switch (apiEntity.getApiType()) {
			case ECR:
				EcrImageScan scan = new EcrImageScan();
				scan.setApiLabel(apiEntity.getApiLabel());
				scan.parseImageScanFromWebhook(imageScan);
				return scan;
			default:
				throw new ApiIntegrationException("No SCM API for this label.");
		}
	}

}
