package com.tracelink.appsec.watchtower.core.ui;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.stream.Stream;

/**
 * Locates every Thymeleaf template directory, and every static JS script
 * directory, across all Maven modules in the reactor. Templates (and
 * scripts) live in {@code watchtower-core} but also in each scan module
 * ({@code watchtower-module-*}) and {@code watchtower-web}, so a test that
 * only looked at its own module's files would silently cover a fraction of
 * what the Phase 11 Bootstrap 5 migration (and the Material Web migration
 * that follows it) tracks.
 *
 * <p>Script scanning exists because a Bootstrap-era construct can be
 * reintroduced as a JS string just as easily as in a template - e.g.
 * {@code advisory-designer.js} and {@code eslint-designer.js} both emit
 * {@code data-toggle="modal"}/{@code class='form-control'} markup as raw
 * strings for DataTables-rendered rows. A scanner that only ever looked at
 * {@code .html} files would never see a regression introduced that way.
 */
final class TemplateModuleScanner {

	private static final String TEMPLATES_RELATIVE_PATH = "src/main/resources/templates";

	private static final String SCRIPTS_RELATIVE_PATH = "src/main/resources/static/scripts";

	private TemplateModuleScanner() {
	}

	/**
	 * Returns every template file, as absolute paths, sorted for
	 * deterministic test output.
	 */
	static List<Path> findAllTemplateFiles() throws IOException {
		List<Path> templateFiles = new ArrayList<>();
		for (Path templatesDir : findTemplateDirectories()) {
			try (Stream<Path> paths = Files.walk(templatesDir)) {
				paths.filter(path -> path.toString().endsWith(".html"))
						.forEach(templateFiles::add);
			}
		}
		templateFiles.sort(Comparator.comparing(Path::toString));
		return templateFiles;
	}

	/**
	 * Same as {@link #findAllTemplateFiles()}, but relative to the reactor
	 * root (e.g. {@code watchtower-core/src/main/resources/templates/profile.html}),
	 * so tests can key off of a stable, machine-independent path.
	 */
	static List<Path> findAllTemplateFilesRelativeToRepoRoot() throws IOException {
		Path repoRoot = findRepoRoot();
		List<Path> relativePaths = new ArrayList<>();
		for (Path absolutePath : findAllTemplateFiles()) {
			relativePaths.add(repoRoot.relativize(absolutePath));
		}
		return relativePaths;
	}

	static Path repoRoot() {
		return findRepoRoot();
	}

	static List<Path> findTemplateDirectories() {
		return findModuleSubdirectories(TEMPLATES_RELATIVE_PATH, /* required= */ true);
	}

	/**
	 * Every {@code .js} file under each module's {@code static/scripts/}
	 * directory, as absolute paths, sorted for deterministic test output.
	 * Not every module ships one (e.g. a module with no designer JS at
	 * all), so unlike {@link #findTemplateDirectories()} finding zero is
	 * not itself an error - only an empty result across the *whole* reactor
	 * would indicate broken repo-root discovery, and that case is already
	 * caught by {@link #findTemplateDirectories()} running first in any
	 * test that needs both.
	 */
	static List<Path> findAllScriptFiles() throws IOException {
		List<Path> scriptFiles = new ArrayList<>();
		for (Path scriptsDir : findModuleSubdirectories(SCRIPTS_RELATIVE_PATH, /* required= */ false)) {
			try (Stream<Path> paths = Files.walk(scriptsDir)) {
				paths.filter(path -> path.toString().endsWith(".js"))
						.forEach(scriptFiles::add);
			}
		}
		scriptFiles.sort(Comparator.comparing(Path::toString));
		return scriptFiles;
	}

	/**
	 * Same as {@link #findAllScriptFiles()}, but relative to the reactor
	 * root, matching {@link #findAllTemplateFilesRelativeToRepoRoot()}'s
	 * shape so a test can key both file kinds off the same kind of path.
	 */
	static List<Path> findAllScriptFilesRelativeToRepoRoot() throws IOException {
		Path repoRoot = findRepoRoot();
		List<Path> relativePaths = new ArrayList<>();
		for (Path absolutePath : findAllScriptFiles()) {
			relativePaths.add(repoRoot.relativize(absolutePath));
		}
		return relativePaths;
	}

	private static List<Path> findModuleSubdirectories(String relativePath, boolean required) {
		Path repoRoot = findRepoRoot();
		List<Path> matchingDirs = new ArrayList<>();
		File[] moduleDirs = repoRoot.toFile().listFiles(File::isDirectory);
		if (moduleDirs != null) {
			for (File moduleDir : moduleDirs) {
				Path candidate = moduleDir.toPath().resolve(relativePath);
				if (Files.isDirectory(candidate)) {
					matchingDirs.add(candidate);
				}
			}
		}
		if (required && matchingDirs.isEmpty()) {
			throw new IllegalStateException(
					"No '" + relativePath + "' directories found under repo root " + repoRoot
							+ " - repo-root discovery is likely broken");
		}
		return matchingDirs;
	}

	/**
	 * Walks up from the current working directory - a single module (e.g.
	 * {@code watchtower-core}) when Maven runs its tests - until it finds the
	 * reactor root, identified by a top-level {@code pom.xml} with packaging
	 * {@code pom} and a {@code <modules>} block.
	 */
	private static Path findRepoRoot() {
		Path startDir = Path.of("").toAbsolutePath();
		Path dir = startDir;
		while (dir != null) {
			Path pom = dir.resolve("pom.xml");
			if (Files.isRegularFile(pom) && isReactorRootPom(pom)) {
				return dir;
			}
			dir = dir.getParent();
		}
		throw new IllegalStateException(
				"Could not locate the watchtower reactor root by walking up from " + startDir);
	}

	private static boolean isReactorRootPom(Path pom) {
		try {
			String content = Files.readString(pom);
			return content.contains("<modules>") && content.contains("<packaging>pom</packaging>");
		} catch (IOException e) {
			return false;
		}
	}
}
