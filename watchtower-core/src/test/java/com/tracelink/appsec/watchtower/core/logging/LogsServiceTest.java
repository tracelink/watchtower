package com.tracelink.appsec.watchtower.core.logging;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.Enumeration;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipException;
import java.util.zip.ZipFile;

import org.apache.commons.io.IOUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.BDDMockito;
import org.slf4j.LoggerFactory;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import com.google.common.io.Files;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.LoggerContext;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.classic.spi.LoggingEvent;
import ch.qos.logback.core.read.CyclicBufferAppender;

@ExtendWith(SpringExtension.class)
public class LogsServiceTest {

	LogsService logsService;

	Logger appLogger;

	@MockBean
	CyclicBufferAppender<ILoggingEvent> mockCyclicAppender;

	@BeforeEach
	public void setup() {
		LoggerContext context = (LoggerContext) LoggerFactory.getILoggerFactory();
		this.appLogger = context.getLogger(LogsService.LOGGER_NAME);
		this.logsService = new LogsService(mockCyclicAppender, appLogger);
		logsService.prepareEncoder();
	}

	@Test
	public void testGetLogsCyclicLess() {
		int numLogs = 1;
		String message = "foobar";

		LoggingEvent log = BDDMockito.mock(LoggingEvent.class);
		BDDMockito.when(log.getFormattedMessage()).thenReturn(message);
		BDDMockito.when(log.getLoggerName()).thenReturn(LogsService.class.getName());
		BDDMockito.when(log.getLevel()).thenReturn(Level.INFO);

		BDDMockito.when(mockCyclicAppender.getLength()).thenReturn(numLogs);
		BDDMockito.when(mockCyclicAppender.get(BDDMockito.anyInt())).thenReturn(log);

		List<String> logs = logsService.getLogs();
		Assertions.assertEquals(numLogs, logs.size());
		Assertions.assertTrue(logs.get(0).contains(message));
	}

	@Test
	public void testGetLogsCyclicBigger() {
		int numLogs = 1;
		String message = "foobar";

		LoggingEvent log = BDDMockito.mock(LoggingEvent.class);
		BDDMockito.when(log.getFormattedMessage()).thenReturn(message);
		BDDMockito.when(log.getLoggerName()).thenReturn(LogsService.class.getName());
		BDDMockito.when(log.getLevel()).thenReturn(Level.INFO);

		BDDMockito.when(mockCyclicAppender.getLength()).thenReturn(100);
		BDDMockito.when(mockCyclicAppender.get(BDDMockito.anyInt())).thenReturn(log);

		List<String> logs = logsService.getLogs(numLogs);
		Assertions.assertEquals(numLogs, logs.size());
		Assertions.assertTrue(logs.get(0).contains(message));
	}

	@Test
	public void testChangeLogLevel() {
		Level orig = logsService.getLogsLevel();
		try {
			logsService.setLogsLevel(Level.WARN);
			Assertions.assertEquals(Level.WARN, logsService.getLogsLevel());
		} finally {
			try {
				logsService.setLogsLevel(orig);
			} catch (NullPointerException exception) {
				// happens in eclipse debugging
			}
		}
	}

	@Test
	public void testZipLogs() throws Exception {
		File logDir = Files.createTempDir();
		byte[] firstFileContents = new byte[512];
		byte[] secondFileContents = new byte[256];
		SecureRandom sr = new SecureRandom();
		sr.nextBytes(firstFileContents);
		sr.nextBytes(secondFileContents);
		File firstFile = new File(logDir, "log1.log");
		File secondFile = new File(logDir, "log2.log");
		Files.write(firstFileContents, firstFile);
		Files.write(secondFileContents, secondFile);

		Path outputDir;
		String storedDir = appLogger.getLoggerContext().getProperty("LOGS_DIR");
		try {
			appLogger.getLoggerContext().putProperty("LOGS_DIR", logDir.getAbsolutePath());
			outputDir = logsService.generateLogsZip();
		} finally {
			appLogger.getLoggerContext().putProperty("LOGS_DIR", storedDir);
		}
		File unzipOutput = Files.createTempDir();
		unzip(outputDir.toFile(), unzipOutput);
		byte[] firstReturned = Files.toByteArray(new File(unzipOutput, "log1.log"));
		byte[] secondReturned = Files.toByteArray(new File(unzipOutput, "log2.log"));

		Assertions.assertArrayEquals(firstFileContents, firstReturned);
		Assertions.assertArrayEquals(secondFileContents, secondReturned);
	}

	private void unzip(File zip, File output) throws ZipException, IOException {
		java.util.zip.ZipFile zipFile = new ZipFile(zip);
		try {
			Enumeration<? extends ZipEntry> entries = zipFile.entries();
			while (entries.hasMoreElements()) {
				ZipEntry entry = entries.nextElement();
				File entryDestination = new File(output, entry.getName());
				if (entry.isDirectory()) {
					entryDestination.mkdirs();
				} else {
					entryDestination.getParentFile().mkdirs();
					try (InputStream in = zipFile.getInputStream(entry)) {
						OutputStream out = new FileOutputStream(entryDestination);
						IOUtils.copy(in, out);
						out.close();
					}
				}
			}
		} finally {
			zipFile.close();
		}
	}
}
