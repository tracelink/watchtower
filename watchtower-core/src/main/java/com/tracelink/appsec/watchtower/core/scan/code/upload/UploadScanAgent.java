package com.tracelink.appsec.watchtower.core.scan.code.upload;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.zip.ZipFile;

import org.apache.commons.io.FileUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.tracelink.appsec.watchtower.core.exception.ScanInitializationException;
import com.tracelink.appsec.watchtower.core.scan.code.AbstractCodeScanAgent;
import com.tracelink.appsec.watchtower.core.scan.code.SecureZipUtils;
import com.tracelink.appsec.watchtower.core.scan.code.report.CodeScanReport;
import com.tracelink.appsec.watchtower.core.scan.code.upload.entity.UploadScanContainerEntity;
import com.tracelink.appsec.watchtower.core.scan.code.upload.entity.UploadViolationEntity;
import com.tracelink.appsec.watchtower.core.scan.code.upload.service.UploadScanResultService;
import com.tracelink.appsec.watchtower.core.scan.storage.S3Service;

/**
 * Handles scanning via file upload. Reports on all findings in the zip file
 *
 * @author csmith
 */
public class UploadScanAgent extends AbstractCodeScanAgent<UploadScanAgent> {
	private static Logger LOG = LoggerFactory.getLogger(UploadScanAgent.class);

	private String storageKey;
	private S3Service s3Service;
	private Path zipFile;
	private UploadScanResultService uploadScanResultService;
	private String uploadTicket;

	public UploadScanAgent(UploadScanContainerEntity upload) {
		super(upload.getName());
		this.uploadTicket = upload.getTicket();
		this.storageKey = upload.getStorageKey();
	}

	/**
	 * Set the {@linkplain UploadScanResultService} for this Agent's configuration
	 *
	 * @param uploadScanResultService the result Service to use
	 * @return this agent
	 */
	public UploadScanAgent withScanResultService(UploadScanResultService uploadScanResultService) {
		this.uploadScanResultService = uploadScanResultService;
		return this;
	}

	/**
	 * Set the {@linkplain S3Service} used to fetch (and, in {@link #clean()}, remove)
	 * the upload's zip when it is S3-backed - item 3.4/3.5's storage. Only required
	 * when {@code upload}'s storage key is an S3 key; a locally-backed upload (item
	 * 3.4's fallback) never calls it.
	 *
	 * @param s3Service the S3 service to use
	 * @return this agent
	 */
	public UploadScanAgent withS3Service(S3Service s3Service) {
		this.s3Service = s3Service;
		return this;
	}

	@Override
	protected void initialize() throws ScanInitializationException {
		super.initialize();
		if (uploadScanResultService == null) {
			throw new ScanInitializationException(
					"Result Service must be configured.");
		}
		if (UploadStorageLocation.isS3(storageKey) && s3Service == null) {
			throw new ScanInitializationException("S3 Service must be configured.");
		}
		this.uploadScanResultService.markScanInProgress(uploadTicket);
		try {
			if (UploadStorageLocation.isS3(storageKey)) {
				zipFile = Files.createTempFile(uploadTicket, ".zip");
				s3Service.downloadRequired(UploadStorageLocation.s3Key(storageKey), zipFile);
			} else {
				zipFile = UploadStorageLocation.localPath(storageKey);
			}
			SecureZipUtils.secureUnzip(new ZipFile(zipFile.toFile()),
					getWorkingDirectory().toFile());
			// A recovered scan reaching this point is the proof that the upload's object
			// survived recovery; it used to be deleted before the agent could open it.
			LOG.debug("Unzipped upload " + uploadTicket + " from " + this.storageKey
					+ " into the working directory");
		} catch (IOException e) {
			throw new ScanInitializationException("Failed to unzip", e);
		}
	}

	@Override
	protected void report(List<CodeScanReport> reports) {
		List<UploadViolationEntity> violations = new ArrayList<>();
		for (CodeScanReport report : reports) {
			report.getViolations().stream().forEach(sv -> {
				UploadViolationEntity ve = new UploadViolationEntity(sv, getWorkingDirectory());
				violations.add(ve);
			});
		}
		this.uploadScanResultService.saveFinalUploadScan(uploadTicket, violations, getExecutionSummary());
		if (shadowComparisonEnabled()) {
			var saved = uploadScanResultService.findUploadScanByTicket(uploadTicket);
			if (saved != null && saved.getLatestUploadScan() != null)
				recordShadowComparison("upload", saved.getLatestUploadScan().getId());
		}
	}

	@Override
	protected void handleScanException(Exception e) {
		LOG.error("Exception while scanning. Scan Name: " + getScanName() + " TicketId: "
				+ uploadTicket, e);
		this.uploadScanResultService.markScanFailed(uploadTicket, e.getMessage());
		if (getExecutionSummary().codeSnapshot() != null) {
			this.uploadScanResultService.saveExecutionSummary(uploadTicket, getExecutionSummary());
		}
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	protected String getMetricType() {
		return "upload";
	}

	@Override
	protected void clean() {
		FileUtils.deleteQuietly(getWorkingDirectory().toFile());
		// For a local-backed upload, zipFile is the persisted upload itself, and
		// deleting it here is the same behavior upload storage had before S3 existed.
		// For an S3-backed upload, zipFile is only the temp download - the persisted
		// copy is the S3 object, deleted separately below.
		if (zipFile != null) {
			FileUtils.deleteQuietly(zipFile.toFile());
		}
		if (UploadStorageLocation.isS3(storageKey) && s3Service != null) {
			s3Service.deleteObject(UploadStorageLocation.s3Key(storageKey));
		}
	}

}
