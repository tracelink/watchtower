package com.tracelink.appsec.watchtower.core.scan.code;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class ScannerFileTypesTest {

	@Test
	void normalize_trimsLowercasesAndRemovesDuplicates() {
		assertThat(ScannerFileTypes.normalize(List.of(" .TF ", ".tf", "Dockerfile", ".yaml")))
				.containsExactly(".tf", "dockerfile", ".yaml");
	}

	@Test
	void normalize_ignoresBlankEntries() {
		assertThat(ScannerFileTypes.normalize(List.of("", "  ", ".java"))).containsExactly(".java");
	}

	@Test
	void normalize_rejectsPathsAndUnsafeCharacters() {
		assertThatThrownBy(() -> ScannerFileTypes.normalize(List.of("src/main.java")))
				.isInstanceOf(IllegalArgumentException.class).hasMessageContaining("src/main.java");
		assertThatThrownBy(() -> ScannerFileTypes.normalize(List.of(".java;rm")))
				.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	void normalize_rejectsTooManyOrTooLongEntries() {
		List<String> many = new java.util.ArrayList<>();
		for (int i = 0; i < ScannerFileTypes.MAX_TYPES + 1; i++) {
			many.add(".e" + i);
		}
		assertThatThrownBy(() -> ScannerFileTypes.normalize(many))
				.isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> ScannerFileTypes.normalize(List.of("." + "a".repeat(80))))
				.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	void matches_extensionIsASuffixMatchIgnoringCase() {
		assertThat(ScannerFileTypes.matches(".tf", "main.tf")).isTrue();
		assertThat(ScannerFileTypes.matches(".tf", "MAIN.TF")).isTrue();
		assertThat(ScannerFileTypes.matches(".tf", "main.tfvars")).isFalse();
		assertThat(ScannerFileTypes.matches(".d.ts", "types.d.ts")).isTrue();
	}

	@Test
	void matches_nameWithoutDotIsAGlobOnTheFileName() {
		assertThat(ScannerFileTypes.matches("dockerfile", "Dockerfile")).isTrue();
		assertThat(ScannerFileTypes.matches("dockerfile*", "Dockerfile.prod")).isTrue();
		assertThat(ScannerFileTypes.matches("dockerfile", "Dockerfile.prod")).isFalse();
		assertThat(ScannerFileTypes.matches("*.dockerfile", "app.dockerfile")).isTrue();
	}

	@Test
	void anyMatch_emptyTypesMeansEveryFile() {
		assertThat(ScannerFileTypes.anyMatch(List.of(), List.of("a.bin"))).isTrue();
		assertThat(ScannerFileTypes.anyMatch(List.of(), List.of())).isTrue();
	}

	@Test
	void anyMatch_usesTheLastPathSegmentOnly() {
		assertThat(ScannerFileTypes.anyMatch(List.of(".java"), List.of("docs/readme.md", "src/A.java")))
				.isTrue();
		assertThat(ScannerFileTypes.anyMatch(List.of(".java"), List.of("src.java/readme.md")))
				.isFalse();
		assertThat(ScannerFileTypes.anyMatch(List.of(".java"), List.of())).isFalse();
	}

	@Test
	void matchedTypes_findsOnlyTheTypesPresentInTheTree(@TempDir Path root) throws IOException {
		Files.createDirectories(root.resolve("infra/deep"));
		Files.writeString(root.resolve("infra/deep/main.tf"), "x");
		Files.writeString(root.resolve("README.md"), "x");

		Set<String> matched = ScannerFileTypes.matchedTypes(root, List.of(".tf", ".java", ".yaml"));

		assertThat(matched).containsExactly(".tf");
	}

	@Test
	void matchedTypes_failsOpenWhenTheDirectoryCannotBeWalked(@TempDir Path root) {
		Set<String> matched =
				ScannerFileTypes.matchedTypes(root.resolve("missing"), List.of(".tf", ".java"));

		assertThat(matched).containsExactlyInAnyOrder(".tf", ".java");
	}

	@Test
	void matches_aHostileFileNameCannotMakeAGlobBacktrackForever() {
		String glob = "*a*a*a*a*a*a*a*a*a*a*b";
		String name = "a".repeat(5000);

		org.junit.jupiter.api.Assertions.assertTimeoutPreemptively(java.time.Duration.ofSeconds(2),
				() -> assertThat(ScannerFileTypes.matches(glob, name)).isFalse());
		assertThat(ScannerFileTypes.matches("*a*b", "xxaxxb")).isTrue();
		assertThat(ScannerFileTypes.matches("a?c", "abc")).isTrue();
		assertThat(ScannerFileTypes.matches("a?c", "ac")).isFalse();
	}

	@Test
	void normalize_collapsesRepeatedStarsAndCapsTheStoredLength() {
		assertThat(ScannerFileTypes.normalize(List.of("a**b***c"))).containsExactly("a*b*c");
		List<String> long64 = new java.util.ArrayList<>();
		for (int i = 0; i < ScannerFileTypes.MAX_TYPES; i++) {
			long64.add("." + String.valueOf((char) ('a' + i % 26)).repeat(60) + i);
		}
		assertThatThrownBy(() -> ScannerFileTypes.normalize(long64))
				.isInstanceOf(IllegalArgumentException.class).hasMessageContaining("too long");
	}

	@Test
	void anyMatch_ignoresNullEntries() {
		List<String> withNull = new java.util.ArrayList<>();
		withNull.add(null);
		withNull.add(".java");
		assertThat(ScannerFileTypes.anyMatch(withNull, java.util.Arrays.asList(null, "A.java"))).isTrue();
	}

	@Test
	void matchedTypes_failsOpenWhenAFolderCannotBeOpened(@TempDir Path root) throws IOException {
		Path locked = Files.createDirectory(root.resolve("locked"));
		Files.writeString(locked.resolve("main.tf"), "x");
		try {
			Files.setPosixFilePermissions(locked, java.util.Set.of());
		} catch (UnsupportedOperationException e) {
			return; // no POSIX permissions on this platform
		}
		try {
			if (Files.isReadable(locked)) {
				return; // running as a user that ignores permissions
			}
			assertThat(ScannerFileTypes.matchedTypes(root, List.of(".tf", ".java")))
					.containsExactlyInAnyOrder(".tf", ".java");
		} finally {
			Files.setPosixFilePermissions(locked,
					java.nio.file.attribute.PosixFilePermissions.fromString("rwx------"));
		}
	}

	@Test
	void matchedTypes_doesNotFollowSymlinks(@TempDir Path root, @TempDir Path outside)
			throws IOException {
		Files.writeString(outside.resolve("secret.tf"), "x");
		try {
			Files.createSymbolicLink(root.resolve("link"), outside);
		} catch (UnsupportedOperationException | IOException e) {
			return; // platform cannot create symlinks; nothing to assert
		}

		assertThat(ScannerFileTypes.matchedTypes(root, List.of(".tf"))).isEmpty();
	}
}
