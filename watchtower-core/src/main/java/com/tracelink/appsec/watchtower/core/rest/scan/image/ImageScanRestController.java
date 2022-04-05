package com.tracelink.appsec.watchtower.core.rest.scan.image;

import javax.servlet.http.HttpServletRequest;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.tracelink.appsec.watchtower.core.exception.ScanRejectedException;
import com.tracelink.appsec.watchtower.core.scan.api.APIIntegrationEntity;
import com.tracelink.appsec.watchtower.core.scan.api.APIIntegrationService;
import com.tracelink.appsec.watchtower.core.scan.api.ApiIntegrationException;
import com.tracelink.appsec.watchtower.core.scan.image.ImageScan;
import com.tracelink.appsec.watchtower.core.scan.image.result.ImageScanResult;
import com.tracelink.appsec.watchtower.core.scan.image.service.ImageScanResultService;
import com.tracelink.appsec.watchtower.core.scan.image.service.ImageScanningService;

@RestController
@RequestMapping("/rest/scan")
@PreAuthorize("permitAll()")
public class ImageScanRestController {
	private static final Logger LOG = LoggerFactory.getLogger(ImageScanRestController.class);

	private ImageScanResultService scanResultService;

	private APIIntegrationService apiService;

	private ImageScanningService imageScanningService;

	public ImageScanRestController(@Autowired ImageScanResultService scanResultService,
			@Autowired APIIntegrationService apiService,
			@Autowired ImageScanningService imageScanningService) {
		this.scanResultService = scanResultService;
		this.apiService = apiService;
		this.imageScanningService = imageScanningService;
	}

	@GetMapping("/result")
	ResponseEntity<ImageScanResult> getResultForTicket(@RequestParam String registry,
			@RequestParam String imageName, @RequestParam String tagName) {
		return ResponseEntity.ok(
				scanResultService.generateResultForCoordinates(registry, imageName, tagName));
	}

	@PostMapping("/{source}")
	ResponseEntity<String> scanImage(@PathVariable String source,
			@RequestBody String imageScan,
			HttpServletRequest request) {
		String responseMessage;
		try {
			APIIntegrationEntity apiEntity = apiService.findByLabel(source);
			if (apiEntity == null) {
				LOG.error("Unsupported api label: " + source);
				throw new ScanRejectedException("Unknown api label");
			}

			ImageScan image = createImageScanFromAutomation(apiEntity, imageScan);
			imageScanningService.doImageScan(image);
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
		if (apiEntity == null) {
			throw new ApiIntegrationException("Entity is null");
		}
		switch (apiEntity.getApiType()) {
			case ECR:
				ImageScan scan = new ImageScan(apiEntity.getApiLabel());
				scan.parseScanFromWebhook(imageScan);
				return scan;
			default:
				throw new ApiIntegrationException("No Image API for this label.");
		}
	}

}
