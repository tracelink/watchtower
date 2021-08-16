package com.tracelink.appsec.watchtower.test.logging;

import java.util.List;
import java.util.stream.Collectors;

import org.junit.jupiter.api.extension.AfterEachCallback;
import org.junit.jupiter.api.extension.BeforeEachCallback;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.slf4j.LoggerFactory;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;

/**
 * JUnit Extension for unit testing log messages in core code. There is an equivalent version of
 * this class in the watchtower-core module to support the same features in watchtower core.
 * 
 * @author csmith
 *
 */
public final class LogWatchExtension implements BeforeEachCallback, AfterEachCallback {

	private ListAppender<ILoggingEvent> listAppender = new ListAppender<>();
	private Logger logger = null;

	private LogWatchExtension(String classLogger) {
		if (classLogger != null) {
			logger = (Logger) LoggerFactory.getLogger(classLogger);
			logger.setLevel(Level.INFO);
		}
	}

	/**
	 * Create a base no-op watcher that will not track log messages. This is useful for situations
	 * where parts of a test suite need the logger and other parts don't.
	 * 
	 * @return a {@linkplain LogWatchExtension} that does not track logs
	 */
	public static LogWatchExtension none() {
		return new LogWatchExtension(null);
	}

	/**
	 * Create a watcher that will track log messages for the given class. This is useful for
	 * situations where a test needs to view the result of a method that might log error conditions,
	 * or success messages. Note that this can be used for classes not under test as well.
	 * 
	 * @param clazz the class to watch logs from
	 * @return a {@linkplain LogWatchExtension} that tracks logs for the given class
	 */
	public static LogWatchExtension forClass(Class<?> clazz) {
		return new LogWatchExtension(clazz.getName());
	}

	/**
	 * Create a watcher that will track log messages for all loggers. This is useful for situations
	 * where a test needs to view the result of an underlying 3rd party method or a system log
	 * message.
	 * 
	 * @return a {@linkplain LogWatchExtension} that tracks logs for all loggers
	 */
	public static LogWatchExtension root() {
		return new LogWatchExtension(Logger.ROOT_LOGGER_NAME);
	}

	/**
	 * Set the log level of this watcher
	 * 
	 * @param level the log level
	 * @return this log watcher
	 */
	public LogWatchExtension withLevel(Level level) {
		logger.setLevel(level);
		return this;
	}

	/**
	 * Get the current list of log messages
	 * 
	 * @return the list of log messages that are being tracked
	 */
	public List<String> getMessages() {
		return listAppender.list.stream().map(e -> e.getMessage()).collect(Collectors.toList());
	}

	/**
	 * Get the current list of formatted log messages
	 * 
	 * @return the list of formatted log messages that are being tracked
	 */
	public List<String> getFormattedMessages() {
		return listAppender.list.stream().map(e -> e.getFormattedMessage())
				.collect(Collectors.toList());
	}

	@Override
	public void afterEach(ExtensionContext context) throws Exception {
		if (logger != null) {
			listAppender.stop();
			listAppender.list.clear();
			logger.detachAppender(listAppender);
		}
	}

	@Override
	public void beforeEach(ExtensionContext context) throws Exception {
		if (logger != null) {
			logger.addAppender(listAppender);
			listAppender.start();
		}
	}

}
