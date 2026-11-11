package com.tracelink.appsec.watchtower.core.scan.code.scm.repo.report;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.Optional;

/**
 * Reports in a local directory, for development and a single pod without S3. Another pod cannot
 * see these files, so a multi-pod deployment must use S3.
 *
 * @author Watchtower
 */
public class LocalRepoReportStore implements RepoReportStore {

	private final Path root;

	public LocalRepoReportStore(Path root) {
		this.root = root.toAbsolutePath().normalize();
	}

	@Override
	public void put(String key, byte[] content, String contentType) throws IOException {
		Path target = resolve(key);
		Files.createDirectories(target.getParent());
		Files.write(target, content);
	}

	@Override
	public Optional<byte[]> get(String key) throws IOException {
		Path source = resolve(key);
		return Files.isRegularFile(source) ? Optional.of(Files.readAllBytes(source))
				: Optional.empty();
	}

	@Override
	public void copy(String fromKey, String toKey) throws IOException {
		Path target = resolve(toKey);
		Files.createDirectories(target.getParent());
		Files.copy(resolve(fromKey), target, StandardCopyOption.REPLACE_EXISTING);
	}

	@Override
	public boolean isShared() {
		return false;
	}

	private Path resolve(String key) throws IOException {
		Path path = root.resolve(key).normalize();
		if (!path.startsWith(root)) {
			throw new IOException("Refusing a report key outside the report directory");
		}
		return path;
	}
}
