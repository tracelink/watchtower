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
import com.tracelink.appsec.watchtower.core.scan.code.processor.MultiThreadedProcessor;
import com.tracelink.appsec.watchtower.core.scan.code.processor.ProcessorSetupException;
import com.tracelink.appsec.watchtower.core.scan.code.report.CodeScanReport;

public class MultiThreadedProcessorTest {

	@Test
	public void testProcessFile() throws Exception {
		Path wd = Files.createTempDirectory(null);
		new File(wd.toFile(), "test1").createNewFile();
		new File(wd.toFile(), "test2").createNewFile();

		CallableCreator processor = (file, ruleset) -> (() -> new CodeScanReport());
		int threads = 1;
		MultiThreadedProcessor mtp = new MultiThreadedProcessor(processor, threads);
		mtp.runScan(null, wd);
		FileUtils.deleteQuietly(wd.toFile());

		MatcherAssert.assertThat(mtp.getReports(), Matchers.hasSize(2));
	}

	@Test
	public void testProcessFileFailed() throws Exception {
		Path wd = Files.createTempDirectory(null);
		new File(wd.toFile(), "test1").createNewFile();
		new File(wd.toFile(), "test2").createNewFile();

		CallableCreator processor = (file, ohter) -> (() -> {
			throw new ProcessorSetupException(new IOException("Some IO Exception"));
		});

		int threads = 1;
		MultiThreadedProcessor mtp = new MultiThreadedProcessor(processor, threads);
		mtp.runScan(null, wd);
		MatcherAssert.assertThat(mtp.getSystemExceptions(), Matchers.hasSize(2));
	}
}
