package com.tracelink.appsec.watchtower.core.scan.code;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Enumeration;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

import org.apache.commons.io.FileUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Zip-slip-safe extraction shared by every place in the scan pipeline that unzips a zip
 * file it did not create itself: {@code UploadScanAgent} (an untrusted user upload,
 * where this logic originated) and the S3 source-zip cache (IMPROVEMENT_PLAN.md item
 * 3.3 - a cache entry this application wrote is still bytes coming back over the
 * network, so it gets the same validation as any other external input, not an
 * exemption). Extracted into its own class rather than duplicated, since a second
 * hand-written path-traversal check is exactly the kind of security-sensitive
 * copy-paste this project's coding standards warn against.
 *
 * @author Watchtower
 */
public final class SecureZipUtils {
	private static final Logger LOG = LoggerFactory.getLogger(SecureZipUtils.class);
	private static final long DEFAULT_MAX_EXTRACTED_BYTES = 2L * 1024 * 1024 * 1024;
	private static final int DEFAULT_MAX_ENTRIES = 100_000;
	private static final double DEFAULT_MAX_COMPRESSION_RATIO = 100D;

	private SecureZipUtils() {
	}

	/**
	 * Unzip a zip file while checking for any Path Traversal vulnerabilities. Writes
	 * files to the file system at the outputDirectory location. If a Path Traversal is
	 * found, unzipping will stop and previous files will be attempted to be deleted.
	 * There is no guarantee that the output will be cleaned completely. Likely-binary
	 * files are deleted right after being written, since no scanner needs them.
	 *
	 * @param zipFile         the zip file to unzip
	 * @param outputDirectory the directory into which zip entries will be written
	 * @throws IOException if an I/O error occurs when reading, writing, or deleting a
	 *                      file, or if a zip entry attempts to write outside
	 *                      outputDirectory. This may cause leftover files to exist in
	 *                      the filesystem
	 */
	public static void secureUnzip(ZipFile zipFile, File outputDirectory) throws IOException {
		secureUnzip(zipFile, outputDirectory, DEFAULT_MAX_EXTRACTED_BYTES, DEFAULT_MAX_ENTRIES,
				DEFAULT_MAX_COMPRESSION_RATIO);
	}

	public static void secureUnzip(ZipFile zipFile, File outputDirectory, long maxExtractedBytes,
			int maxEntries, double maxCompressionRatio) throws IOException {
		if (zipFile.size() > maxEntries) throw new IOException("Zip archive contains too many entries");
		// Reject Unix links/devices before extraction. java.util.zip otherwise hides mode metadata.
		try (var metadata = new net.lingala.zip4j.ZipFile(zipFile.getName())) {
			for (var header : metadata.getFileHeaders()) {
				byte[] attrs = header.getExternalFileAttributes();
				int kind = attrs == null || attrs.length < 4 ? 0 : (attrs[3] & 0xf0);
				if (kind != 0 && kind != 0x80 && kind != 0x40) throw new IOException("Zip contains a link or special file");
			}
		}
		Enumeration<? extends ZipEntry> entries = zipFile.entries();
		long extractedBytes = 0;
		int entryCount = 0;

		try {
			while (entries.hasMoreElements()) {
				ZipEntry entry = entries.nextElement();
				if (++entryCount > maxEntries) {
					throw new IOException("Zip archive contains too many entries");
				}
				String entryName = entry.getName();
				if (entryName.startsWith("/") || entryName.contains("\\") || entryName.matches("^[A-Za-z]:.*")) throw new IOException("Invalid zip path");
				File destination = new File(outputDirectory, entryName);

				// if a problem occurs, short-circuit
				if (!isSubPath(outputDirectory.toPath(), destination.toPath())) {
					throw new IOException(String.format(
							"Zip entry %s in zip file %s is attempting to access an illegal location and has been blocked",
							entryName, zipFile.getName()));
				}
				Path base = outputDirectory.toPath().toAbsolutePath().normalize();
				for (Path component = destination.toPath().toAbsolutePath().normalize(); component != null && component.startsWith(base); component = component.getParent()) {
					if (Files.isSymbolicLink(component)) throw new IOException("Linked extraction path");
				}

				long compressedSize = entry.getCompressedSize();
				long declaredSize = entry.getSize();
				if (compressedSize > 0 && declaredSize > 0
						&& (double) declaredSize / compressedSize > maxCompressionRatio) {
					throw new IOException("Zip entry exceeds the allowed compression ratio");
				}

				if (entry.isDirectory()) {
					Files.createDirectories(destination.toPath());
				} else {
					Files.createDirectories(destination.getParentFile().toPath());
					try (InputStream in = zipFile.getInputStream(entry);
							OutputStream out = Files.newOutputStream(destination.toPath())) {
						byte[] buffer = new byte[8192];
						int read;
						while ((read = in.read(buffer)) != -1) {
							extractedBytes += read;
							if (extractedBytes > maxExtractedBytes) {
								throw new IOException("Zip archive exceeds the extracted size limit");
							}
							out.write(buffer, 0, read);
						}
					}
					if (FileTypeUtils.isBinary(destination.toPath())) {
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

	private static boolean isSubPath(Path basePath, Path targetPath) {
		Path normalizedBase = basePath.toAbsolutePath().normalize();
		Path normalizedTest = targetPath.toAbsolutePath().normalize();
		return normalizedTest.startsWith(normalizedBase);
	}
}
