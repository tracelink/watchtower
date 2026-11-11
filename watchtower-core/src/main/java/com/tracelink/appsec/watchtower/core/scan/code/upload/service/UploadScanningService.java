package com.tracelink.appsec.watchtower.core.scan.code.upload.service;

import ch.qos.logback.classic.Level;
import com.tracelink.appsec.watchtower.core.exception.ScanRejectedException;
import com.tracelink.appsec.watchtower.core.exception.rule.RulesetNotFoundException;
import com.tracelink.appsec.watchtower.core.logging.LogsService;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetEntity;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetService;
import com.tracelink.appsec.watchtower.core.scan.AbstractScanningService;
import com.tracelink.appsec.watchtower.core.scan.ScanRegistrationService;
import com.tracelink.appsec.watchtower.core.scan.ScanStatus;
import com.tracelink.appsec.watchtower.core.scan.code.upload.UploadScan;
import com.tracelink.appsec.watchtower.core.scan.code.upload.UploadScanAgent;
import com.tracelink.appsec.watchtower.core.scan.code.upload.UploadStorageLocation;
import com.tracelink.appsec.watchtower.core.scan.code.upload.entity.UploadScanContainerEntity;
import com.tracelink.appsec.watchtower.core.scan.storage.S3Service;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.RejectedExecutionException;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.MeterRegistry;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

/**
 * Manages creating scans for Uploads
 *
 * @author csmith
 */
@Service
public class UploadScanningService extends AbstractScanningService {
	@org.springframework.beans.factory.annotation.Autowired(required = false)
	private com.tracelink.appsec.watchtower.core.rule.candidate.RuleShadowService candidateShadow;


	private static final Logger LOG = LoggerFactory.getLogger(UploadScanningService.class);

	private final LogsService logService;
	private final RulesetService rulesetService;
	private final ScanRegistrationService scanRegistrationService;
	private final UploadScanResultService uploadScanResultService;
	private final S3Service s3Service;
	private final Path localWorkDir;
	private final MeterRegistry meterRegistry;
	private final Counter scanQueuedCounter;

	public UploadScanningService(@Autowired LogsService logService,
			@Autowired RulesetService rulesetService,
			@Autowired ScanRegistrationService scanRegistrationService,
			@Autowired UploadScanResultService uploadScanResultService,
			@Autowired S3Service s3Service,
			@Autowired MeterRegistry meterRegistry,
			@Value("${watchtower.threads.uploadscan:2}") int threads,
			@Value("${watchtower.runAfterStartup:true}") boolean recoverFromDowntime) {
		super(threads, recoverFromDowntime);
		this.logService = logService;
		this.rulesetService = rulesetService;
		this.scanRegistrationService = scanRegistrationService;
		this.uploadScanResultService = uploadScanResultService;
		this.s3Service = s3Service;
		this.localWorkDir = Paths.get("./upload").toAbsolutePath();
		this.meterRegistry = meterRegistry;
		this.scanQueuedCounter = Counter.builder("watchtower.scan.queued")
				.tag("type", "upload")
				.register(meterRegistry);
		Gauge.builder("watchtower.scan.queue.depth", this, UploadScanningService::getTaskNumInQueue)
				.tag("type", "upload")
				.register(meterRegistry);
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
		if (!scanRegistrationService.hasCodeScanners()) {
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
				.withCandidateShadow(candidateShadow)
				.withScanners(scanRegistrationService.getCodeScanners())
				.withRuleset(ruleset.toDto())
				.withScanResultService(uploadScanResultService)
				.withS3Service(s3Service)
				.withMeterRegistry(meterRegistry)
				.withBenchmarkEnabled(!logService.getLogsLevel().isGreaterOrEqual(Level.INFO));

		CompletableFuture.runAsync(scanAgent, getExecutor());
		scanQueuedCounter.increment();
	}

	/**
	 * Streams a {@linkplain MultipartFile} to S3 under a freshly minted key, falling
	 * back to the local {@code ./upload} directory when S3 is not configured. Either
	 * way the key does not need to match the scan's ticket, since
	 * {@linkplain UploadScanContainerEntity#getStorageKey()} is what ties a scan to its
	 * stored zip, not the key's shape - see {@linkplain UploadStorageLocation}.
	 *
	 * @param uploadFile the uploaded file
	 * @return the storage key the upload was stored under
	 * @throws IOException if the upload fails, in S3 or on local disk
	 */
	public String storeUpload(MultipartFile uploadFile) throws IOException {
		if (s3Service.isEnabled()) {
			String key = "uploads/" + UUID.randomUUID() + ".zip";
			s3Service.uploadRequired(key, uploadFile.getInputStream(), uploadFile.getSize());
			return UploadStorageLocation.forS3Key(key);
		}
		// Created on demand rather than trusting the constructor-time check. workDir is
		// a relative path on the pod's disk, so it can disappear underneath a running
		// instance - a cleanup job, or an emptyDir volume being replaced - and uploads
		// would then fail until the pod restarted. createDirectories is a no-op when it
		// already exists.
		Files.createDirectories(localWorkDir);
		Path zipLocation = Files.createTempFile(localWorkDir, null, null);
		try (InputStream in = uploadFile.getInputStream();
				OutputStream out = Files.newOutputStream(zipLocation)) {
			IOUtils.copyLarge(in, out);
		}
		return UploadStorageLocation.forLocalPath(zipLocation);
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
		if (inProgressScans.isEmpty() && notStartedScans.isEmpty()) {
			LOG.info("No Upload Scans found to recover after downtime");
		}
	}

	private void restartScans(List<UploadScanContainerEntity> scans) {
		for (UploadScanContainerEntity scan : scans) {
			String storageKey = scan.getStorageKey();
			if (storageExists(storageKey)) {
				try {
					RulesetEntity ruleset = rulesetService.getRuleset(scan.getRuleSet());
					// Ownership of the stored zip passes to the agent, which removes it in
					// UploadScanAgent.clean(). Deleting it here would race the scan we
					// just queued: submitScan() returns as soon as the agent is handed to
					// the executor, not when it has finished reading it.
					submitScan(scan, ruleset);
					LOG.info("Resubmitted recovered upload scan " + scan.getTicket()
							+ "; object retained at " + storageKey
							+ " for the scan agent to consume");
				} catch (RulesetNotFoundException e) {
					uploadScanResultService.markScanFailed(scan.getTicket(),
							"Scan was canceled due to system downtime and could not be recovered as the ruleset is invalid. Resubmit this request");
					// No agent was submitted, so nothing else will clean this up.
					deleteStorage(storageKey);
				}
			} else {
				uploadScanResultService.markScanFailed(scan.getTicket(),
						"Scan was canceled due to system downtime and could not be recovered as the zip file no longer exists. Resubmit this request");
			}
		}
	}

	private boolean storageExists(String storageKey) {
		if (UploadStorageLocation.isS3(storageKey)) {
			return s3Service.keyExists(UploadStorageLocation.s3Key(storageKey));
		}
		return UploadStorageLocation.localPath(storageKey).toFile().exists();
	}

	private void deleteStorage(String storageKey) {
		if (UploadStorageLocation.isS3(storageKey)) {
			s3Service.deleteObject(UploadStorageLocation.s3Key(storageKey));
		} else {
			FileUtils.deleteQuietly(UploadStorageLocation.localPath(storageKey).toFile());
		}
	}

}
