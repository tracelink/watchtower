package com.tracelink.appsec.module.pmd;

import java.util.List;
import java.util.stream.Collectors;

import org.junit.rules.TestRule;
import org.junit.runner.Description;
import org.junit.runners.model.Statement;
import org.slf4j.LoggerFactory;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;

public class LoggerRule implements TestRule {

	private ListAppender<ILoggingEvent> listAppender = new ListAppender<>();
	private Logger logger = null;

	private LoggerRule(String classLogger) {
		if (classLogger != null) {
			logger = (Logger) LoggerFactory.getLogger(classLogger);
		}
	}

	public static LoggerRule none() {
		return new LoggerRule(null);
	}

	public static LoggerRule forClass(Class<?> clazz) {
		return new LoggerRule(clazz.getName());
	}

	public static LoggerRule root() {
		return new LoggerRule(Logger.ROOT_LOGGER_NAME);
	}

	@Override
	public Statement apply(Statement base, Description description) {
		return new Statement() {
			@Override
			public void evaluate() throws Throwable {
				setup();
				base.evaluate();
				teardown();
			}
		};
	}

	private void setup() {
		if (logger != null) {
			logger.addAppender(listAppender);
			listAppender.start();
		}
	}

	private void teardown() {
		if (logger != null) {
			listAppender.stop();
			listAppender.list.clear();
			logger.detachAppender(listAppender);
		}
	}

	public List<String> getMessages() {
		return listAppender.list.stream().map(e -> e.getMessage()).collect(Collectors.toList());
	}

	public List<String> getFormattedMessages() {
		return listAppender.list.stream().map(e -> e.getFormattedMessage()).collect(Collectors.toList());
	}

}