package com.tracelink.appsec.watchtower.core.process;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Duration;
import java.util.concurrent.TimeUnit;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * Runs external binaries safely for scanner modules.
 * <ul>
 * <li>stdout and stderr are drained concurrently, so a process can never block on a full pipe;</li>
 * <li>a hard timeout kills the process and all of its descendants;</li>
 * <li>captured output is capped per stream, with the excess drained and discarded;</li>
 * <li>process output and arguments are never logged — only the executable name, exit code and
 * timing — because scanner output can contain secrets.</li>
 * </ul>
 */
@Component
public class ProcessRunner {

	private static final Logger LOGGER = LoggerFactory.getLogger(ProcessRunner.class);
	private static final Duration KILL_GRACE = Duration.ofSeconds(5);
	private static final int READ_BUFFER_BYTES = 8192;

	/**
	 * Runs the requested process to completion or timeout.
	 *
	 * @param request what to run
	 * @return the captured result; check {@link ProcessResult#isSuccess()}
	 * @throws ProcessExecutionException if the process cannot be started or the calling thread is
	 *                                   interrupted while waiting
	 */
	public ProcessResult run(ProcessRequest request) {
		String name = executableName(request);
		ProcessBuilder builder = new ProcessBuilder(request.command());
		if (request.environment() != null) {
			builder.environment().clear();
			builder.environment().putAll(request.environment());
		}
		if (request.workingDirectory() != null) {
			builder.directory(request.workingDirectory().toFile());
		}
		long start = System.nanoTime();
		Process process;
		try {
			process = builder.start();
		} catch (IOException e) {
			throw new ProcessExecutionException("Cannot start process: " + name, e);
		}
		closeQuietly(process.getOutputStream());
		BoundedCapture stdout = new BoundedCapture(process.getInputStream(),
				request.maxOutputBytes());
		BoundedCapture stderr = new BoundedCapture(process.getErrorStream(),
				request.maxOutputBytes());
		Thread stdoutReader = Thread.ofVirtual().name("process-stdout-" + name).start(stdout);
		Thread stderrReader = Thread.ofVirtual().name("process-stderr-" + name).start(stderr);

		boolean finished = awaitProcess(process, request.timeout(), name);
		awaitReaders(process, stdoutReader, stderrReader, name);

		Duration elapsed = Duration.ofNanos(System.nanoTime() - start);
		int exitCode = finished ? process.exitValue() : ProcessResult.TIMED_OUT_EXIT_CODE;
		if (finished) {
			LOGGER.debug("Process {} finished: exit={}, elapsedMs={}", name, exitCode,
					elapsed.toMillis());
		} else {
			LOGGER.warn("Process {} exceeded timeout of {} ms and was killed", name,
					request.timeout().toMillis());
		}
		return new ProcessResult(exitCode, stdout.text(), stderr.text(), !finished,
				stdout.truncated(), stderr.truncated(), elapsed);
	}

	private static boolean awaitProcess(Process process, Duration timeout, String name) {
		try {
			if (process.waitFor(timeout.toMillis(), TimeUnit.MILLISECONDS)) {
				return true;
			}
			killTree(process);
			process.waitFor(KILL_GRACE.toMillis(), TimeUnit.MILLISECONDS);
			return false;
		} catch (InterruptedException e) {
			killTree(process);
			Thread.currentThread().interrupt();
			throw new ProcessExecutionException("Interrupted while running process: " + name, e);
		}
	}

	private static void awaitReaders(Process process, Thread stdoutReader, Thread stderrReader,
			String name) {
		try {
			stdoutReader.join(KILL_GRACE.toMillis());
			stderrReader.join(KILL_GRACE.toMillis());
		} catch (InterruptedException e) {
			Thread.currentThread().interrupt();
			throw new ProcessExecutionException("Interrupted while reading process output: " + name,
					e);
		} finally {
			// Unblock readers if an orphaned grandchild still holds the pipes open
			closeQuietly(process.getInputStream());
			closeQuietly(process.getErrorStream());
		}
	}

	private static void killTree(Process process) {
		process.descendants().forEach(ProcessHandle::destroyForcibly);
		process.destroyForcibly();
	}

	private static String executableName(ProcessRequest request) {
		Path fileName = Path.of(request.command().get(0)).getFileName();
		return fileName == null ? request.command().get(0) : fileName.toString();
	}

	private static void closeQuietly(AutoCloseable closeable) {
		try {
			closeable.close();
		} catch (Exception e) {
			LOGGER.trace("Ignoring failure closing process stream", e);
		}
	}

	/**
	 * Drains a stream fully, keeping at most {@code maxBytes}.
	 */
	private static final class BoundedCapture implements Runnable {

		private final InputStream input;
		private final long maxBytes;
		private final ByteArrayOutputStream captured = new ByteArrayOutputStream();
		private boolean truncated;

		BoundedCapture(InputStream input, long maxBytes) {
			this.input = input;
			this.maxBytes = maxBytes;
		}

		@Override
		public void run() {
			byte[] buffer = new byte[READ_BUFFER_BYTES];
			try (input) {
				int read;
				while ((read = input.read(buffer)) != -1) {
					append(buffer, read);
				}
			} catch (IOException e) {
				// Stream closed after timeout or process exit; keep what was captured
				LOGGER.trace("Process stream closed while reading", e);
			}
		}

		private synchronized void append(byte[] buffer, int length) {
			long remaining = maxBytes - captured.size();
			if (remaining <= 0) {
				truncated = true;
				return;
			}
			int toWrite = (int) Math.min(remaining, length);
			captured.write(buffer, 0, toWrite);
			if (toWrite < length) {
				truncated = true;
			}
		}

		synchronized String text() {
			return captured.toString(StandardCharsets.UTF_8);
		}

		synchronized boolean truncated() {
			return truncated;
		}
	}
}
