package com.tracelink.appsec.watchtower.core.rest.scan.upload;

import com.tracelink.appsec.watchtower.core.auth.model.CorePrivilege;
import com.tracelink.appsec.watchtower.core.exception.ScanRejectedException;
import com.tracelink.appsec.watchtower.core.scan.code.upload.UploadScan;
import com.tracelink.appsec.watchtower.core.scan.code.upload.result.UploadScanResult;
import com.tracelink.appsec.watchtower.core.scan.code.upload.service.UploadScanResultService;
import com.tracelink.appsec.watchtower.core.scan.code.upload.service.UploadScanningService;
import java.io.IOException;
import java.nio.file.Path;
import java.security.Principal;
import java.util.Optional;
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
import org.springframework.web.multipart.MultipartFile;

/**
 * Controller for all REST API calls. Handles a health check and sending a scan via REST.
 *
 * @author csmith
 */
@RestController
@RequestMapping("/rest/uploadscan")
@PreAuthorize("hasAuthority('" + CorePrivilege.SCAN_SUBMIT_NAME + "')")
public class UploadScanRestController {

	private static final Logger LOG = LoggerFactory.getLogger(UploadScanRestController.class);

	private UploadScanningService scanService;

	private UploadScanResultService uploadScanResultService;

	public UploadScanRestController(@Autowired UploadScanningService scanService,
			@Autowired UploadScanResultService uploadScanResultService) {
		this.scanService = scanService;
		this.uploadScanResultService = uploadScanResultService;
	}

	@PostMapping()
	ResponseEntity<UploadScanResult> scanUpload(@RequestParam Optional<String> name,
			@RequestParam Optional<String> ruleset, @RequestBody MultipartFile uploadFile,
			Principal userPrincipal) {
		String uploadName = name.orElse(uploadFile.getOriginalFilename());
		String rulesetName = ruleset.orElse(null);

		UploadScan upload = new UploadScan();
		String ticket;
		try {
			upload.setName(uploadName);
			upload.setRuleSetName(rulesetName);
			upload.setUser(userPrincipal == null ? "" : userPrincipal.getName());

			Path zipLocation = scanService.copyToLocation(uploadFile);
			upload.setFilePath(zipLocation);

			ticket = scanService.doUploadScan(upload);
		} catch (ScanRejectedException e) {
			return ResponseEntity.badRequest().body(
					uploadScanResultService.generateFailedUploadResult(upload, e.getMessage()));
		} catch (IOException e) {
			LOG.error("Error copying the file", e);
			return ResponseEntity.badRequest()
					.body(uploadScanResultService.generateFailedUploadResult(upload,
							"Error copying the file: " + e.getMessage()));
		}

		return ResponseEntity.ok(uploadScanResultService.generateResultForTicket(ticket));
	}

	@GetMapping("/{ticket}")
	ResponseEntity<UploadScanResult> getResultForTicket(@PathVariable String ticket) {
		return ResponseEntity.ok(uploadScanResultService.generateResultForTicket(ticket));
	}
}
