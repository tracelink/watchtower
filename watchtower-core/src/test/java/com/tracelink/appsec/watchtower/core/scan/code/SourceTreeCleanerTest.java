package com.tracelink.appsec.watchtower.core.scan.code;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Set;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

public class SourceTreeCleanerTest {

	@TempDir
	Path root;

	private Path write(String relative, byte[] content) throws IOException {
		Path file = root.resolve(relative);
		Files.createDirectories(file.getParent());
		return Files.write(file, content);
	}

	@Test
	public void deletesExcludedFoldersAnywhereInTheTree() throws IOException {
		Path kept = write("src/App.java", "class App {}".getBytes());
		Path nested = write("web/node_modules/lib/index.js", "x".getBytes());
		Path top = write("test/AppTest.java", "class AppTest {}".getBytes());

		SourceTreeCleaner.clean(root, Set.of("test", "node_modules"));

		Assertions.assertTrue(Files.exists(kept));
		Assertions.assertFalse(Files.exists(nested));
		Assertions.assertFalse(Files.exists(top));
	}

	@Test
	public void deletesUninterestingExtensionsAndBinaryContent() throws IOException {
		Path jar = write("lib/a.jar", "PK".getBytes());
		Path image = write("img/logo.png", "png".getBytes());
		Path binary = write("bin/blob.dat", new byte[] {0, 1, 2, 0, 0, 3});
		Path text = write("README.md", "# readme".getBytes());

		SourceTreeCleaner.clean(root, Set.of());

		Assertions.assertFalse(Files.exists(jar));
		Assertions.assertFalse(Files.exists(image));
		Assertions.assertFalse(Files.exists(binary));
		Assertions.assertTrue(Files.exists(text));
	}
}
