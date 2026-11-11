package com.tracelink.appsec.watchtower.core.process;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Objects;

/**
 * Immutable description of an external process to run with {@link ProcessRunner}.
 *
 * @param command          the executable and its arguments; copied defensively
 * @param workingDirectory the directory to run in, or null for the current directory
 * @param timeout          hard limit after which the process (and its children) are killed
 * @param maxOutputBytes   cap applied separately to captured stdout and stderr; output beyond
 *                         the cap is drained and discarded so the process never blocks
 * @param environment     null to inherit the current environment; an explicit map replaces it
 */
public record ProcessRequest(List<String> command, Path workingDirectory, Duration timeout,
		long maxOutputBytes, java.util.Map<String, String> environment) {
	public ProcessRequest(List<String> command, Path workingDirectory, Duration timeout, long maxOutputBytes) {
		this(command, workingDirectory, timeout, maxOutputBytes, null);
	}

	public ProcessRequest {
		Objects.requireNonNull(command, "command must not be null");
		if (command.isEmpty() || command.stream().anyMatch(Objects::isNull)) {
			throw new IllegalArgumentException("command must be non-empty with no null elements");
		}
		command = List.copyOf(command);
		if (environment != null) environment = java.util.Map.copyOf(environment);
		Objects.requireNonNull(timeout, "timeout must not be null");
		if (timeout.isZero() || timeout.isNegative()) {
			throw new IllegalArgumentException("timeout must be positive");
		}
		if (maxOutputBytes <= 0) {
			throw new IllegalArgumentException("maxOutputBytes must be positive");
		}
		if (workingDirectory != null && !Files.isDirectory(workingDirectory)) {
			throw new IllegalArgumentException("workingDirectory must be an existing directory");
		}
	}
}
