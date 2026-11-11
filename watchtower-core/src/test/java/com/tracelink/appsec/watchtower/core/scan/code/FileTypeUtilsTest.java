package com.tracelink.appsec.watchtower.core.scan.code;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

public class FileTypeUtilsTest {

	@TempDir
	Path tempDir;

	@Test
	public void testTextFileIsNotBinary() throws Exception {
		Path file = tempDir.resolve("Example.java");
		Files.write(file, "public class Example {\n\tint x = 1;\n}\n"
				.getBytes(StandardCharsets.UTF_8));

		Assertions.assertFalse(FileTypeUtils.isBinary(file));
	}

	@Test
	public void testBinaryFileIsBinary() throws Exception {
		// A compiled class starts with the 0xCAFEBABE magic number followed by bytes
		// that are mostly unprintable.
		Path file = tempDir.resolve("Example.class");
		byte[] content = new byte[512];
		content[0] = (byte) 0xCA;
		content[1] = (byte) 0xFE;
		content[2] = (byte) 0xBA;
		content[3] = (byte) 0xBE;
		Files.write(file, content);

		Assertions.assertTrue(FileTypeUtils.isBinary(file));
	}

	@Test
	public void testBinaryContentUnderATextExtensionIsStillBinary() throws Exception {
		// The whole point of sampling content: an extension blocklist cannot catch this.
		Path file = tempDir.resolve("bundle.js");
		byte[] content = new byte[400];
		for (int i = 0; i < content.length; i++) {
			content[i] = (byte) (i % 8);
		}
		Files.write(file, content);

		Assertions.assertTrue(FileTypeUtils.isBinary(file));
	}

	@Test
	public void testEmptyFileIsNotBinary() throws Exception {
		Path file = tempDir.resolve("empty.txt");
		Files.createFile(file);

		// Nothing sampled means nothing to suggest binary, and an empty file is
		// harmless to scan. This also pins that no divide-by-zero occurs.
		Assertions.assertFalse(FileTypeUtils.isBinary(file));
	}

	@Test
	public void testUnreadableFileIsTreatedAsBinary() {
		// Skipping is safer than handing an unreadable path to a scanner.
		Assertions.assertTrue(FileTypeUtils.isBinary(tempDir.resolve("does-not-exist")));
	}

	@Test
	public void testFileJustUnderTheThresholdIsBinary() throws Exception {
		// 90 printable bytes in 100 is below the 95% threshold.
		Path file = tempDir.resolve("mixed.txt");
		byte[] content = new byte[100];
		for (int i = 0; i < 90; i++) {
			content[i] = 'a';
		}
		for (int i = 90; i < 100; i++) {
			content[i] = 0x00;
		}
		Files.write(file, content);

		Assertions.assertTrue(FileTypeUtils.isBinary(file));
	}
}
