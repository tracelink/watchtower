package com.tracelink.appsec.watchtower.core.rest.scan.image;

import com.tracelink.appsec.watchtower.core.auth.model.CorePrivilege;
import com.tracelink.appsec.watchtower.core.exception.ScanRejectedException;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.ApiIntegrationEntity;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.ApiIntegrationException;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.ApiIntegrationService;
import com.tracelink.appsec.watchtower.core.scan.image.ImageScan;
import com.tracelink.appsec.watchtower.core.scan.image.api.ecr.EcrImageScan;
import com.tracelink.appsec.watchtower.core.scan.image.service.ImageScanningService;
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

@RestController
@RequestMapping("/rest/imagescan")
public class ImageScanRestController {

	private static final Logger LOG = LoggerFactory.getLogger(ImageScanRestController.class);

	private final ImageScanningService scanService;
	private final ApiIntegrationService apiService;

	public ImageScanRestController(@Autowired ImageScanningService scanService,
			@Autowired ApiIntegrationService apiService) {
		this.scanService = scanService;
		this.apiService = apiService;
	}

	@PostMapping("/{source}")
	@PreAuthorize("authentication.getName().equals(#source) && hasAuthority('"
			+ CorePrivilege.INTEGRATION_SCAN_SUBMIT + "')")
	ResponseEntity<String> scanImageRequest(@PathVariable String source,
			@RequestBody String imageScan) {
		try {
			ApiIntegrationEntity apiEntity = apiService.findByLabel(source);
			if (apiEntity == null) {
				LOG.error("Unsupported api label: " + source);
				throw new ScanRejectedException("Unknown api label");
			}

			ImageScan scan = createImageScanFromAutomation(apiEntity, imageScan);
			scanService.doImageScan(scan);
			return ResponseEntity.ok("Added scan successfully");
		} catch (ScanRejectedException e) {
			return ResponseEntity.badRequest().body(e.getMessage());
		} catch (Exception e) {
			LOG.error("Error adding the scan", e);
			return ResponseEntity.badRequest().body("Error adding the scan: " + e.getMessage());
		}
	}

	private ImageScan createImageScanFromAutomation(ApiIntegrationEntity apiEntity,
			String imageScan) throws ApiIntegrationException {
		switch (apiEntity.getApiType()) {
			case ECR:
				EcrImageScan scan = new EcrImageScan(apiEntity.getApiLabel());
				scan.populateFromRequest(imageScan);
				return scan;
			default:
				throw new ApiIntegrationException("No SCM API for this label.");
		}
	}

}
