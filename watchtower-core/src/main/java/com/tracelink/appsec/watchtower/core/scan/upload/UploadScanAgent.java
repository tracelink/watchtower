package com.tracelink.appsec.watchtower.core.scan.upload;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

import org.apache.commons.io.FileUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.tracelink.appsec.watchtower.core.exception.ScanInitializationException;
import com.tracelink.appsec.watchtower.core.report.ScanReport;
import com.tracelink.appsec.watchtower.core.scan.AbstractScanAgent;
import com.tracelink.appsec.watchtower.core.scan.upload.entity.UploadScanContainerEntity;
import com.tracelink.appsec.watchtower.core.scan.upload.entity.UploadViolationEntity;
import com.tracelink.appsec.watchtower.core.scan.upload.service.UploadScanResultService;

/**
 * Handles scanning via file upload. Reports on all findings in the zip file
 *
 * @author csmith
 */
public class UploadScanAgent extends AbstractScanAgent<UploadScanAgent> {
	private static Logger LOG = LoggerFactory.getLogger(UploadScanAgent.class);

	private Path workingDirectory;
	private Path zipFile;
	private UploadScanResultService uploadScanResultService;
	private String uploadTicket;

	public UploadScanAgent(UploadScanContainerEntity upload) {
		super(upload.getName());
		this.uploadTicket = upload.getTicket();
		this.workingDirectory = createWorkingDirectory();
		this.zipFile = upload.getZipPath();
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

	@Override
	protected void initialize() throws ScanInitializationException {
		super.initialize();
		if (uploadScanResultService == null) {
			throw new ScanInitializationException(
					"Result Service must be configured.");
		}
		this.uploadScanResultService.markScanInProgress(uploadTicket);
		try {
			secureUnzipBlock(new ZipFile(this.zipFile.toFile()), workingDirectory.toFile());
		} catch (IOException e) {
			throw new ScanInitializationException("Failed to unzip", e);
		}
	}

	@Override
	protected void report(List<ScanReport> reports) {
		List<UploadViolationEntity> violations = new ArrayList<>();
		for (ScanReport report : reports) {
			report.getViolations().stream().forEach(sv -> {
				UploadViolationEntity ve = new UploadViolationEntity(sv, getWorkingDirectory());
				violations.add(ve);
			});
		}
		this.uploadScanResultService.saveFinalUploadScan(uploadTicket, violations);
	}

	@Override
	protected Path getWorkingDirectory() {
		return workingDirectory;
	}

	@Override
	protected void handleScanException(Exception e) {
		LOG.error("Exception while scanning. Scan Name: " + getScanName() + " TicketId: "
				+ uploadTicket, e);
		this.uploadScanResultService.markScanFailed(uploadTicket, e.getMessage());
	}

	@Override
	protected void clean() {
		FileUtils.deleteQuietly(workingDirectory.toFile());
		FileUtils.deleteQuietly(zipFile.toFile());
	}

	/**
	 * Unzip a zip file while checking for any Path Traversal vulnerabilities. Writes files to the
	 * file system at the outputDirectory location. If a Path Traversal is found, unzipping will
	 * stop and previous files will be attempted to be deleted. There is no guarantee that the
	 * output will be cleaned completely.
	 * 
	 * @param zipFile         the zip file to unzip
	 * @param outputDirectory the directory into which zip entries will be written
	 * @throws PathTraversalSecurityException if any entry in the zip file attempts to write to a
	 *                                        parent or sibling location
	 * @throws IOException                    if an I/O error occurs when reading, writing, or
	 *                                        deleting a file. This may cause leftover files to
	 *                                        exist in the filesystem
	 */
	private void secureUnzipBlock(ZipFile zipFile, File outputDirectory)
			throws IOException {
		Enumeration<? extends ZipEntry> entries = zipFile.entries();

		try {
			while (entries.hasMoreElements()) {
				ZipEntry entry = entries.nextElement();
				String entryName = entry.getName();
				File destination = new File(outputDirectory, entryName);

				// if a problem occurs, short-circuit
				if (!isSubPath(outputDirectory.toPath(), destination.toPath())) {
					throw new IOException(String.format(
							"Zip entry %s in zip file %s is attempting to access an illegal location and has been blocked",
							entryName, zipFile.getName()));
				}

				if (entry.isDirectory()) {
					destination.mkdirs();
				} else {
					destination.getParentFile().mkdirs();
					try (InputStream in = zipFile.getInputStream(entry)) {
						Files.copy(in, destination.toPath());
					}
					if (isBinary(destination)) {
						LOG.debug("Skipping likely binary file " + destination.toString());
						FileUtils.deleteQuietly(destination);
					}
				}
			}
		} catch (IOException e) {
			// There was a vuln found, try to roll-back
			FileUtils.deleteQuietly(outputDirectory);
			throw e;
		}
	}

	private boolean isBinary(File destination) {
		int countPrintable = 0;
		int countNotPrintable = 0;
		int count = 0;

		try (FileInputStream fis = new FileInputStream(destination)) {
			byte[] bytes = new byte[1000];
			count = fis.read(bytes);
			for (int i = 0; i < count; i++) {
				byte b = bytes[i];
				if ((b > 31 && b < 127) || b == '\t' || b == '\n' || b == '\r' || b == '\f') {
					countPrintable++;
				} else {
					countNotPrintable++;
				}
			}
		} catch (IOException e) {
			return true;
		}
		if (count == -1) {
			return false;
		}
		return (countPrintable * 100) / (countPrintable + countNotPrintable) < 95;
	}

	private boolean isSubPath(Path basePath, Path targetPath) {
		Path normalizedBase = basePath.normalize();
		Path normalizedTest = targetPath.normalize();
		return normalizedTest.startsWith(normalizedBase);
	}

}
