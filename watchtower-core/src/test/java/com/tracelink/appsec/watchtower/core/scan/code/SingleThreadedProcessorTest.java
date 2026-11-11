package com.tracelink.appsec.watchtower.core.scan.code;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import org.apache.commons.io.FileUtils;
import org.hamcrest.MatcherAssert;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.Test;

import com.tracelink.appsec.watchtower.core.scan.code.processor.CallableCreator;
import com.tracelink.appsec.watchtower.core.scan.code.processor.ProcessorSetupException;
import com.tracelink.appsec.watchtower.core.scan.code.processor.SingleThreadedProcessor;
import com.tracelink.appsec.watchtower.core.scan.code.report.CodeScanReport;

public class SingleThreadedProcessorTest {

	@Test
	public void testProcessFile() throws Exception {
		Path wd = Files.createTempDirectory(null);
		new File(wd.toFile(), "test1").createNewFile();
		new File(wd.toFile(), "test2").createNewFile();

		CallableCreator processor = (file, ruleset) -> (() -> new CodeScanReport());
		SingleThreadedProcessor stp = new SingleThreadedProcessor(processor);
		stp.runScan(null, wd);
		FileUtils.deleteQuietly(wd.toFile());

		MatcherAssert.assertThat(stp.getReports(), Matchers.hasSize(2));
	}

	@Test
	public void testOnlyFilesOfTheGivenTypesAreHandedToTheScanner() throws Exception {
		Path wd = Files.createTempDirectory(null);
		new File(wd.toFile(), "a.js").createNewFile();
		new File(wd.toFile(), "B.java").createNewFile();
		new File(wd.toFile(), "logo.png").createNewFile();
		java.util.List<String> seen = new java.util.ArrayList<>();

		CallableCreator processor = (file, ruleset) -> {
			seen.add(file.getFileName().toString());
			return () -> new CodeScanReport();
		};
		SingleThreadedProcessor stp = new SingleThreadedProcessor(processor);
		stp.withFileTypes(java.util.List.of(".js"));
		stp.runScan(null, wd);
		FileUtils.deleteQuietly(wd.toFile());

		MatcherAssert.assertThat(seen, Matchers.contains("a.js"));
	}

	@Test
	public void testNoFileTypesMeansEveryFile() throws Exception {
		Path wd = Files.createTempDirectory(null);
		new File(wd.toFile(), "a.js").createNewFile();
		new File(wd.toFile(), "logo.png").createNewFile();

		SingleThreadedProcessor stp = new SingleThreadedProcessor((file, ruleset) -> () -> new CodeScanReport());
		stp.withFileTypes(java.util.List.of());
		stp.runScan(null, wd);
		FileUtils.deleteQuietly(wd.toFile());

		MatcherAssert.assertThat(stp.getReports(), Matchers.hasSize(2));
	}

	@Test
	public void testProcessFileFailed() throws Exception {
		Path wd = Files.createTempDirectory(null);
		new File(wd.toFile(), "test1").createNewFile();
		new File(wd.toFile(), "test2").createNewFile();

		CallableCreator processor = (file, ruleset) -> (() -> {
			throw new ProcessorSetupException(new IOException("Some IO Exception"));
		});

		SingleThreadedProcessor stp = new SingleThreadedProcessor(processor);
		stp.runScan(null, wd);
		MatcherAssert.assertThat(stp.getSystemExceptions(), Matchers.hasSize(2));
	}
}
