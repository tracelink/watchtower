package com.tracelink.appsec.watchtower.core.scan.code;

import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipOutputStream;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class SecureZipUtilsTest {
	@TempDir Path tempDir;

	@Test
	void rejectsArchiveThatExceedsExtractedByteLimit() throws Exception {
		Path archive = archiveWith("large.txt", new byte[128]);
		try (ZipFile zip = new ZipFile(archive.toFile())) {
			assertThrows(IOException.class, () -> SecureZipUtils.secureUnzip(
					zip, tempDir.resolve("out").toFile(), 64, 10, 100));
		}
		Path traversal = archiveWith("../outside.txt", new byte[] {1});
		try (ZipFile zip = new ZipFile(traversal.toFile())) {
			assertThrows(IOException.class, () -> SecureZipUtils.secureUnzip(zip, tempDir.resolve("out").toFile()));
		}
		org.junit.jupiter.api.Assertions.assertFalse(Files.exists(tempDir.resolve("outside.txt")));
		Path symlink = archiveWith("linked.txt", new byte[] {1});
		byte[] bytes = Files.readAllBytes(symlink);
		for (int i = 0; i < bytes.length - 42; i++) {
			if (bytes[i] == 'P' && bytes[i+1] == 'K' && bytes[i+2] == 1 && bytes[i+3] == 2) { bytes[i+41] = (byte) 0xa1; break; }
		}
		Files.write(symlink, bytes);
		try (ZipFile zip = new ZipFile(symlink.toFile())) {
			assertThrows(IOException.class, () -> SecureZipUtils.secureUnzip(zip, tempDir.resolve("out").toFile()));
		}
	}

	@Test
	void rejectsArchiveThatExceedsEntryLimit() throws Exception {
		Path archive = tempDir.resolve("entries.zip");
		try (OutputStream out = Files.newOutputStream(archive);
				ZipOutputStream zip = new ZipOutputStream(out)) {
			for (int i = 0; i < 3; i++) {
				zip.putNextEntry(new ZipEntry("file-" + i + ".txt"));
				zip.write(i);
				zip.closeEntry();
			}
		}
		try (ZipFile zip = new ZipFile(archive.toFile())) {
			assertThrows(IOException.class, () -> SecureZipUtils.secureUnzip(
					zip, tempDir.resolve("out").toFile(), 1024, 2, 100));
		}
	}

	private Path archiveWith(String name, byte[] content) throws IOException {
		Path archive = tempDir.resolve("archive.zip");
		try (OutputStream out = Files.newOutputStream(archive);
				ZipOutputStream zip = new ZipOutputStream(out)) {
			zip.putNextEntry(new ZipEntry(name));
			zip.write(content);
			zip.closeEntry();
		}
		return archive;
	}
}
