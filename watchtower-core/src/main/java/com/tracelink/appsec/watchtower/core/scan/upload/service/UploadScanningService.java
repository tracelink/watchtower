package com.tracelink.appsec.watchtower.core.scan.upload.service;

import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.RejectedExecutionException;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import com.tracelink.appsec.watchtower.core.exception.ScanRejectedException;
import com.tracelink.appsec.watchtower.core.exception.rule.RulesetNotFoundException;
import com.tracelink.appsec.watchtower.core.logging.LogsService;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetEntity;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetService;
import com.tracelink.appsec.watchtower.core.scan.AbstractScanningService;
import com.tracelink.appsec.watchtower.core.scan.ScanRegistrationService;
import com.tracelink.appsec.watchtower.core.scan.ScanStatus;
import com.tracelink.appsec.watchtower.core.scan.upload.UploadScan;
import com.tracelink.appsec.watchtower.core.scan.upload.UploadScanAgent;
import com.tracelink.appsec.watchtower.core.scan.upload.entity.UploadScanContainerEntity;

import ch.qos.logback.classic.Level;

/**
 * Manages creating scans for Uploads
 * 
 * @author csmith
 *
 */
@Service
public class UploadScanningService extends AbstractScanningService {
	private static Logger LOG = LoggerFactory.getLogger(UploadScanningService.class);

	private LogsService logService;

	private RulesetService rulesetService;

	private ScanRegistrationService scanRegistrationService;

	private UploadScanResultService uploadScanResultService;

	private Path workDir;

	public UploadScanningService(@Autowired LogsService logService,
			@Autowired RulesetService rulesetService,
			@Autowired ScanRegistrationService scanRegistrationService,
			@Autowired UploadScanResultService uploadScanResultService) {
		super(2);
		this.logService = logService;
		this.rulesetService = rulesetService;
		this.scanRegistrationService = scanRegistrationService;
		this.uploadScanResultService = uploadScanResultService;

		this.workDir = Paths.get("./upload").toAbsolutePath();
		if (!Files.exists(this.workDir)) {
			this.workDir.toFile().mkdirs();
		}
	}

	/**
	 * Queue a new Scan onto the next available async thread.
	 *
	 * @param upload an object describing the upload request to review
	 * @return the ticket id
	 * @throws RejectedExecutionException if the async manager cannot handle another task
	 * @throws ScanRejectedException      If the scan could not be started due to a configuration
	 *                                    problem
	 */
	public String doUploadScan(UploadScan upload)
			throws RejectedExecutionException, ScanRejectedException {
		String name = upload.getName();
		if (isQuiesced()) {
			String message = "Quiesced. Did not schedule Upload Scan: " + name;
			LOG.error(message);
			throw new ScanRejectedException(message);
		}
		String rulesetName = upload.getRuleSetName();
		RulesetEntity ruleset;
		try {
			ruleset = StringUtils.isBlank(rulesetName) ? rulesetService.getDefaultRuleset()
					: rulesetService.getRuleset(rulesetName);
			upload.setRuleSetName(ruleset.getName());
		} catch (RulesetNotFoundException e) {
			throw new ScanRejectedException("Unknown Ruleset", e);
		}

		// Skip scan if there are no scanners configured
		if (scanRegistrationService.isEmpty()) {
			String message =
					"Upload Scan: " + name + " skipped as there are no scanners configured.";
			LOG.info(message);
			throw new ScanRejectedException(message);
		}

		UploadScanContainerEntity uploadStub = uploadScanResultService.makeNewScanEntity(upload);

		submitScan(uploadStub, ruleset);

		return uploadStub.getTicket();
	}

	private void submitScan(UploadScanContainerEntity upload, RulesetEntity ruleset) {
		// Create scan agent
		UploadScanAgent scanAgent = new UploadScanAgent(upload)
				.withScanners(scanRegistrationService.getScanners())
				.withRuleset(ruleset.toDto())
				.withScanResultService(uploadScanResultService)
				.withBenchmarkEnabled(!logService.getLogsLevel().isGreaterOrEqual(Level.INFO));

		CompletableFuture.runAsync(scanAgent, getExecutor());
	}

	/**
	 * Copy the contents of a {@linkplain MultipartFile} to the working directory
	 * 
	 * @param uploadFile the uploaded file
	 * @return the path to the copied file in the working directory
	 * @throws IOException if the copy fails
	 */
	public Path copyToLocation(MultipartFile uploadFile) throws IOException {
		Path zipLocation = Files.createTempFile(workDir, null, null);
		FileOutputStream fos = new FileOutputStream(zipLocation.toFile());
		IOUtils.copyLarge(uploadFile.getInputStream(), fos);
		return zipLocation;
	}

	@Override
	protected void recoverFromDowntime() {
		// Recover scans that were in progress/not started if possible
		List<UploadScanContainerEntity> inProgressScans =
				uploadScanResultService.findUploadsByStatus(ScanStatus.IN_PROGRESS);
		List<UploadScanContainerEntity> notStartedScans =
				uploadScanResultService.findUploadsByStatus(ScanStatus.NOT_STARTED);

		if (!inProgressScans.isEmpty()) {
			LOG.info("Attempting to recover In Progress Upload Scans after downtime");
			restartScans(inProgressScans);
		}
		if (!notStartedScans.isEmpty()) {
			LOG.info("Attempting to recover Not Started Upload Scans after downtime");
			restartScans(notStartedScans);
		}
	}

	private void restartScans(List<UploadScanContainerEntity> scans) {
		for (UploadScanContainerEntity scan : scans) {
			if (scan.getZipPath().toFile().exists()) {
				RulesetEntity ruleset;
				try {
					ruleset = rulesetService.getRuleset(scan.getRuleSet());
					submitScan(scan, ruleset);
				} catch (RulesetNotFoundException e) {
					uploadScanResultService.markScanFailed(scan.getTicket(),
							"Scan was canceled due to system downtime and could not be recovered as the ruleset is invalid. Resubmit this request");
				} finally {
					FileUtils.deleteQuietly(scan.getZipPath().toFile());
				}
			} else {
				uploadScanResultService.markScanFailed(scan.getTicket(),
						"Scan was canceled due to system downtime and could not be recovered as the zip file no longer exists. Resubmit this request");
			}
		}
	}

}
