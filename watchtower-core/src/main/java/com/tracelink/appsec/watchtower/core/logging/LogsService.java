package com.tracelink.appsec.watchtower.core.logging;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import javax.annotation.PostConstruct;

import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.encoder.PatternLayoutEncoder;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.CyclicBufferAppender;

/**
 * Handles all logic around Logging and loggers
 *
 * @author csmith
 */
@Service
public class LogsService {
	/**
	 * The name of the Watchtower logger
	 */
	public static final String LOGGER_NAME = "com.tracelink.appsec";
	/**
	 * The name of the Queue appender to get the most recent logs
	 */
	public static final String APPENDER_NAME = "ROLLING-QUEUE";
	private static final int DEFAULT_LOGS_NUMBER = 256;
	private static final String PATTERN_LAYOUT =
			"%d{yyyy-MM-dd HH:mm:ss.SSS} %logger{36} %-5level - %msg%n";

	private static Logger LOG = (Logger) LoggerFactory.getLogger(LogsService.class);

	private CyclicBufferAppender<ILoggingEvent> cyclicAppender;

	private Logger appLogger;

	private PatternLayoutEncoder encoder;

	public LogsService(@Autowired CyclicBufferAppender<ILoggingEvent> cyclicAppender,
			@Autowired Logger appLogger) {
		this.cyclicAppender = cyclicAppender;
		this.appLogger = appLogger;
	}

	/**
	 * Once the application is live, setup its patterns
	 */
	@PostConstruct
	public void prepareEncoder() {
		encoder = new PatternLayoutEncoder();
		encoder.setContext(appLogger.getLoggerContext());
		encoder.setPattern(PATTERN_LAYOUT);
		encoder.start();
	}

	/**
	 * Get the most recent number of logs, up to the length of the appender as defined by its max
	 * size {@link LogsService#DEFAULT_LOGS_NUMBER}
	 *
	 * @param number the number of logs requested
	 * @return a list of logs of either number size or the most the queue has
	 */
	public List<String> getLogs(int number) {
		int length = cyclicAppender.getLength();
		int returnSize = Math.min(number, length);
		List<String> logs = new ArrayList<String>(returnSize);
		for (int i = 1; i <= returnSize; i++) {
			logs.add(new String(encoder.encode(cyclicAppender.get(length - i))));
		}
		return logs;
	}

	/**
	 * Sets the logger level for the Watchtower logger
	 *
	 * @param level the level to set to
	 */
	public void setLogsLevel(Level level) {
		appLogger.setLevel(level);
		LOG.warn("Logger updated to: " + level.levelStr);
	}

	/**
	 * Return up to {@linkplain LogsService#DEFAULT_LOGS_NUMBER}
	 *
	 * @return all of the most recent logs
	 */
	public List<String> getLogs() {
		return this.getLogs(DEFAULT_LOGS_NUMBER);
	}

	/**
	 * Get the logger level for the Watchtower logger
	 *
	 * @return the Watchtower logger level
	 */
	public Level getLogsLevel() {
		return appLogger.getLevel();
	}

	/**
	 * Zip all contents in the logs directory and create a zip file. Return the path to the zip
	 *
	 * @return the path to the zip of all logs
	 * @throws IOException if a filesystem error occurs
	 */
	public Path generateLogsZip() throws IOException {
		Path logDir = Paths.get(appLogger.getLoggerContext().getProperty("LOGS_DIR"));
		Path target = Files.createTempFile(null, ".zip");
		zipLogs(logDir, target);
		return target;
	}

	private void zipLogs(Path logDir, Path target) throws IOException {
		try (ZipOutputStream zs = new ZipOutputStream(Files.newOutputStream(target))) {
			Files.walk(logDir).filter(path -> !Files.isDirectory(path)).forEach(path -> {
				ZipEntry zipEntry = new ZipEntry(logDir.relativize(path).toString());
				try {
					zs.putNextEntry(zipEntry);
					Files.copy(path, zs);
					zs.closeEntry();
				} catch (IOException e) {
					LOG.error("Error while zipping", e);
				}
			});
		}
	}
}
