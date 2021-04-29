package com.tracelink.appsec.watchtower.core.scan;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import org.apache.commons.io.FileUtils;
import org.hamcrest.MatcherAssert;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.Test;

import com.tracelink.appsec.watchtower.core.report.ScanReport;
import com.tracelink.appsec.watchtower.core.scan.processor.CallableCreator;
import com.tracelink.appsec.watchtower.core.scan.processor.ProcessorSetupException;
import com.tracelink.appsec.watchtower.core.scan.processor.SingleThreadedProcessor;

public class SingleThreadedProcessorTest {

	@Test
	public void testProcessFile() throws Exception {
		Path wd = Files.createTempDirectory(null);
		new File(wd.toFile(), "test1").createNewFile();
		new File(wd.toFile(), "test2").createNewFile();

		CallableCreator processor = (file, ruleset) -> (() -> new ScanReport());
		SingleThreadedProcessor stp = new SingleThreadedProcessor(processor);
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
