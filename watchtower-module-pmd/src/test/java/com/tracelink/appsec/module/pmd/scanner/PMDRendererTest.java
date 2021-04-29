package com.tracelink.appsec.module.pmd.scanner;

import java.io.IOException;
import java.io.InputStream;
import java.io.Writer;
import java.util.List;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.mockito.BDDMockito;

import com.tracelink.appsec.watchtower.test.logging.LogWatchExtension;

import net.sourceforge.pmd.benchmark.TimingReport;
import net.sourceforge.pmd.util.datasource.DataSource;

public class PMDRendererTest {

	@RegisterExtension
	public LogWatchExtension loggerRule = LogWatchExtension.forClass(PMDReport.class);

	@Test
	public void testNoOpWriterEnforcement() throws Exception {
		PMDRenderer renderer = new PMDRenderer();
		Writer writer = BDDMockito.mock(Writer.class);
		renderer.setWriter(writer);

		BDDMockito.verify(writer).close();
		Assertions.assertEquals(NoopWriter.class.getName(),
				renderer.getWriter().getClass().getName());

		BDDMockito.willThrow(IOException.class).given(writer).close();
		renderer.setWriter(writer);
		// no throws happened, writer was captured
		BDDMockito.verify(writer, BDDMockito.times(2)).close();
		Assertions.assertEquals(NoopWriter.class.getName(),
				renderer.getWriter().getClass().getName());

		// no other good place to ensure this. it's kind of part of the no-op-ness
		Assertions.assertNull(renderer.defaultFileExtension());
	}

	@Test
	public void testAnalysisFlowWithTimingReport() throws Exception {
		PMDRenderer renderer = new PMDRenderer();
		TimingReport timingReport = BDDMockito.mock(TimingReport.class);

		renderer.start();
		Thread.sleep(100);
		renderer.startFileAnalysis(new MockDataSource());
		renderer.end();
		PMDReport report = renderer.createReport();
		report.logRuleBenchmarking();
		// test nothing happened with no timingreport
		Assertions.assertTrue(loggerRule.getMessages().isEmpty());

		renderer.addTimingReport(timingReport);
		report = renderer.createReport();
		report.logRuleBenchmarking();
		// test timing report exists
		List<String> messages = loggerRule.getMessages();
		Assertions.assertEquals(1, messages.size());
		Assertions.assertTrue(messages.get(0).contains("Wall Clock Time"));
	}

	static class MockDataSource implements DataSource {
		@Override
		public InputStream getInputStream() throws IOException {
			return null;
		}

		@Override
		public String getNiceFileName(boolean shortNames, String inputFileName) {
			return inputFileName;
		}

		@Override
		public void close() throws IOException {

		}
	}

}
