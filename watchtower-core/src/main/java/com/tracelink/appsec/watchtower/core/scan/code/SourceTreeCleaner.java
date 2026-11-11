package com.tracelink.appsec.watchtower.core.scan.code;

import java.io.IOException;
import java.nio.file.FileVisitResult;
import java.nio.file.FileVisitor;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.Set;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.FilenameUtils;

/**
 * Trims a downloaded repository to what scanners can use: folders every scanner excludes, and
 * files no scanner reads (archives, images, any content that samples as binary), are deleted
 * before scanning. Shared by every scan that downloads a whole repository.
 *
 * @author Watchtower
 */
public final class SourceTreeCleaner {

	private static final Set<String> UNINTERESTING_FILE_TYPES = Set.of("jar", "png", "jpg");

	private SourceTreeCleaner() {
	}

	/**
	 * @param root            the downloaded repository root
	 * @param excludedFolders folder names to delete wherever they appear
	 * @throws IOException if the tree cannot be walked
	 */
	public static void clean(Path root, Set<String> excludedFolders) throws IOException {
		Files.walkFileTree(root, new FileVisitor<Path>() {
			@Override
			public FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes attrs) {
				if (excludedFolders.contains(dir.getFileName().toString())) {
					FileUtils.deleteQuietly(dir.toFile());
					return FileVisitResult.SKIP_SUBTREE;
				}
				return FileVisitResult.CONTINUE;
			}

			@Override
			public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) {
				// The extension blocklist misses compiled classes, minified bundles and
				// binary assets saved under unexpected names, so sample the content too.
				if (UNINTERESTING_FILE_TYPES
						.contains(FilenameUtils.getExtension(file.getFileName().toString()))
						|| FileTypeUtils.isBinary(file)) {
					FileUtils.deleteQuietly(file.toFile());
					return FileVisitResult.SKIP_SUBTREE;
				}
				return FileVisitResult.CONTINUE;
			}

			@Override
			public FileVisitResult visitFileFailed(Path file, IOException exc) {
				return FileVisitResult.CONTINUE;
			}

			@Override
			public FileVisitResult postVisitDirectory(Path dir, IOException exc) {
				return FileVisitResult.CONTINUE;
			}
		});
	}
}
