package com.tracelink.appsec.watchtower.core.scan.code;

import java.io.IOException;
import java.io.InputStream;
import java.net.JarURLConnection;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.jar.JarFile;

import com.tracelink.appsec.watchtower.core.module.scanner.ICodeScanner;
import com.tracelink.appsec.watchtower.core.rule.RuleRevision;

/**
 * Evidence for self-contained Java engines. Adapters enumerate the artifacts that implement
 * detection and source processing; an unreadable/unsupported artifact leaves provenance unknown.
 * Class names, bytecode hashes and explicitly named public engine resources enter the evidence,
 * never deployment paths, application configuration, credentials or source text. Re-read artifacts
 * at capture time so replacement builds invalidate reuse even when a release's advertised version is unchanged.
 */
public final class JavaEngineExecutionIdentity {

	private JavaEngineExecutionIdentity() {}

	public static EngineExecutionIdentity capture(String engine, ICodeScanner scanner,
			CodeScanConfig config, Class<?>... artifacts) {
		return capture(engine, scanner, config, null, Set.of(), artifacts);
	}

	/**
	 * For engines with runtime-discovered providers or transitive parser dependencies. Records
	 * classpath order and explicitly named public engine resources, without hashing its paths.
	 */
	public static EngineExecutionIdentity captureClasspath(String engine, ICodeScanner scanner,
			CodeScanConfig config, ClassLoader loader, Set<String> publicResourcePrefixes,
			Class<?>... artifacts) {
		if (loader == null || publicResourcePrefixes.stream().anyMatch(String::isBlank)) {
			return EngineExecutionIdentity.unknown(engine);
		}
		return capture(engine, scanner, config, loader, publicResourcePrefixes, artifacts);
	}

	private static EngineExecutionIdentity capture(String engine, ICodeScanner scanner,
			CodeScanConfig config, ClassLoader loader, Set<String> resourcePrefixes, Class<?>... artifacts) {
		try {
			if (artifacts.length == 0) return EngineExecutionIdentity.unknown(engine);
			// A rule subclass can override detection while inheriting a known managed revision.
			var supported = scanner.getSupportedRuleClass();
			if (config.getRuleset() != null && config.getRuleset().getAllRules().stream()
					.anyMatch(rule -> supported.stream().anyMatch(type -> type.isInstance(rule))
							&& !supported.contains(rule.getClass()))) {
				return EngineExecutionIdentity.unknown(engine);
			}
			Map<URL, Artifact> hashes = new HashMap<>();
			RuleRevision implementation = RuleRevision.definition(engine, "java-bytecode-v1");
			if (loader != null) {
				List<URL> locations = runtimeLocations(loader);
				int index = 0;
				for (URL location : locations) {
					Artifact evidence = readArtifact(location, resourcePrefixes, true);
					hashes.put(location, evidence);
					implementation.field("classpath-" + index++, evidence.hash());
				}
			}
			for (Class<?> artifact : artifacts) {
				URL location = artifact.getProtectionDomain().getCodeSource().getLocation();
				Artifact evidence = hashes.get(location);
				if (evidence == null) {
					if (loader != null) throw new IOException("Class absent from runtime classpath");
					evidence = readArtifact(location);
					hashes.put(location, evidence);
				}
				// A containing launcher archive is not evidence for classes in its nested JARs.
				evidence.requireClass(artifact.getName().replace('.', '/') + ".class");
				implementation.field(artifact.getName(), evidence.hash());
			}
			String implementationHash = implementation.hash();
			String version = Runtime.version() + "/sha256:" + implementationHash;
			String configuration = RuleRevision.definition(engine, "java-execution-v1")
					.field("implementation", implementationHash)
					.field("runtime", System.getProperty("java.runtime.version"))
					.field("vendor", System.getProperty("java.vendor"))
					.field("vm", System.getProperty("java.vm.name"))
					.field("vmVersion", System.getProperty("java.vm.version"))
					.field("multiReleaseEnabled", System.getProperty("jdk.util.jar.enableMultiRelease"))
					.field("multiReleaseVersion", System.getProperty("jdk.util.jar.version"))
					.field("os", System.getProperty("os.name"))
					.field("architecture", System.getProperty("os.arch"))
					.field("charset", java.nio.charset.Charset.defaultCharset().name())
					.field("locale", Locale.getDefault().toLanguageTag())
					.field("threads", Integer.toString(config.getThreads()))
					.field("scope", scanner.getRequiredScope().name())
					.unordered("patterns", scanner.getRequiredFilePatterns())
					.unordered("excludedFolders", scanner.getExcludedFolders())
					.hash();
			return new EngineExecutionIdentity(engine, version, configuration, true);
		} catch (IOException | RuntimeException exception) {
			return EngineExecutionIdentity.unknown(engine);
		}
	}

	static List<URL> runtimeLocations(ClassLoader loader) throws IOException {
		if (loader == null || loader == ClassLoader.getPlatformClassLoader()) return List.of();
		var locations = new java.util.ArrayList<URL>(runtimeLocations(loader.getParent()));
		if (loader == ClassLoader.getSystemClassLoader()
				&& loader.getClass().getName().equals("jdk.internal.loader.ClassLoaders$AppClassLoader")) {
			// Extra named modules are outside this classpath contract.
			if (ModuleLayer.boot().configuration().modules().stream().anyMatch(module ->
					module.reference().location().map(uri -> !"jrt".equals(uri.getScheme())).orElse(true))) {
				throw new IOException("Unsupported module path");
			}
			String classpath = System.getProperty("java.class.path");
			if (classpath == null) throw new IOException("Missing runtime classpath");
			for (String entry : classpath.split(java.util.regex.Pattern.quote(java.io.File.pathSeparator), -1)) {
				// An empty entry denotes the process directory, which must be covered as well.
				locations.add(Path.of(entry).toAbsolutePath().normalize().toUri().toURL());
			}
		} else if (loader instanceof URLClassLoader urls && (loader.getClass() == URLClassLoader.class
				|| loader.getClass().getName().equals("org.springframework.boot.loader.launch.LaunchedClassLoader"))) {
			locations.addAll(List.of(urls.getURLs()));
		} else {
			throw new IOException("Unsupported runtime classloader");
		}
		return List.copyOf(locations);
	}

	/** Same digest for exploded classes and JARs, independent of paths/ZIP ordering/timestamps. */
	static String hashClasses(URL location) throws IOException {
		return readArtifact(location).hash();
	}

	static record Artifact(String hash, Set<String> classes) {
		void requireClass(String name) throws IOException {
			if (!classes.contains(name)) throw new IOException("Class absent from execution artifact");
		}
	}

	static Artifact readArtifact(URL location) throws IOException {
		return readArtifact(location, Set.of(), false);
	}

	static Artifact readArtifact(URL location, Set<String> resourcePrefixes, boolean allowEmpty) throws IOException {
		RuleRevision bytes = RuleRevision.definition("java-artifact", "classes-v2");
		Set<String> classes = new java.util.HashSet<>();
		if ("file".equals(location.getProtocol()) && location.getPath().endsWith("/")) {
			bytes.field("multiRelease", "false").field("sealed", "false");
			Path root;
			try {
				root = Path.of(location.toURI());
			} catch (java.net.URISyntaxException exception) {
				throw new IOException("Unsupported artifact location", exception);
			}
			try (var paths = Files.walk(root)) {
				for (Path path : paths.sorted().toList()) {
					if (Files.isSymbolicLink(path)) throw new IOException("Unsupported artifact link");
					if (Files.isDirectory(path)) continue;
					String name = root.relativize(path).toString().replace('\\', '/');
					if (!included(name, resourcePrefixes)) continue;
					if (!Files.isRegularFile(path)) {
						throw new IOException("Unsupported class entry");
					}
					try (InputStream input = Files.newInputStream(path)) {
						bytes.field(name, hash(input));
					}
					if (name.endsWith(".class")) classes.add(name);
				}
			}
		} else {
			URL resource = "jar".equals(location.getProtocol()) ? location
					: new URL("jar:" + location.toExternalForm() + "!/");
			var connection = resource.openConnection();
			if (!(connection instanceof JarURLConnection jarConnection)) {
				throw new IOException("Unsupported artifact protocol");
			}
			jarConnection.setUseCaches(false);
			try (JarFile jar = jarConnection.getJarFile()) {
				var manifest = jar.getManifest();
				var attributes = manifest == null ? new java.util.jar.Attributes() : manifest.getMainAttributes();
				if (attributes.getValue(java.util.jar.Attributes.Name.CLASS_PATH) != null) {
					throw new IOException("Unsupported manifest classpath");
				}
				bytes.field("multiRelease", Boolean.toString(jar.isMultiRelease()))
						.field("sealed", Boolean.toString("true".equalsIgnoreCase(attributes.getValue("Sealed"))));
				if (manifest != null) manifest.getEntries().forEach((name, values) -> {
					String sealed = values.getValue("Sealed");
					if (sealed != null) bytes.field("sealed:" + name, Boolean.toString("true".equalsIgnoreCase(sealed)));
				});
				for (var entry : jar.stream().filter(e -> !e.isDirectory()
						&& included(e.getName(), resourcePrefixes)).sorted(java.util.Comparator
								.comparing(java.util.jar.JarEntry::getName)).toList()) {
					try (InputStream input = jar.getInputStream(entry)) {
						bytes.field(entry.getName(), hash(input));
					}
					if (entry.getName().endsWith(".class")) classes.add(entry.getName());
				}
			}
		}
		if (!allowEmpty && classes.isEmpty()) throw new IOException("No executable classes in artifact");
		return new Artifact(bytes.hash(), Set.copyOf(classes));
	}

	private static boolean included(String name, Set<String> prefixes) {
		return name.endsWith(".class") || prefixes.stream().anyMatch(name::startsWith);
	}

	private static String hash(InputStream input) throws IOException {
		try {
			var digest = java.security.MessageDigest.getInstance("SHA-256");
			byte[] buffer = new byte[8192];
			int length;
			while ((length = input.read(buffer)) != -1) digest.update(buffer, 0, length);
			return java.util.HexFormat.of().formatHex(digest.digest());
		} catch (java.security.NoSuchAlgorithmException exception) {
			throw new IllegalStateException("SHA-256 is unavailable", exception);
		}
	}
}
