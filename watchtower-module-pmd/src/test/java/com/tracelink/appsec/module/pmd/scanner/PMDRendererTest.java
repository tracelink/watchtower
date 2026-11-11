package com.tracelink.appsec.module.pmd.scanner;

import java.io.IOException;
import java.io.Writer;
import java.util.List;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.mockito.BDDMockito;

import com.tracelink.appsec.watchtower.test.logging.LogWatchExtension;

import net.sourceforge.pmd.benchmark.TimingReport;
import net.sourceforge.pmd.reporting.Report;

public class PMDRendererTest {

	@RegisterExtension
	public LogWatchExtension loggerRule = LogWatchExtension.forClass(PMDReport.class);

	@Test
	public void testNoOpWriterEnforcement() throws Exception {
		// PMD 7's AbstractRenderer.setWriter(Writer) always wraps whatever is passed in a new
		// PrintWriter (confirmed via javap: the underlying field is a PrintWriter, not a plain
		// Writer, unlike PMD 6). That means getWriter() can no longer be asserted to return our
		// exact NoopWriter instance/class - only that (a) any real writer passed in is
		// immediately closed and never used, and (b) writing through the result doesn't throw or
		// do anything surprising.
		PMDRenderer renderer = new PMDRenderer();
		Writer writer = BDDMockito.mock(Writer.class);
		renderer.setWriter(writer);

		BDDMockito.verify(writer).close();
		Assertions.assertDoesNotThrow(() -> renderer.getWriter().write("should be discarded"));

		BDDMockito.willThrow(IOException.class).given(writer).close();
		renderer.setWriter(writer);
		// no throws happened, writer was captured
		BDDMockito.verify(writer, BDDMockito.times(2)).close();
		Assertions.assertDoesNotThrow(() -> renderer.getWriter().write("should be discarded"));

		// no other good place to ensure this. it's kind of part of the no-op-ness
		Assertions.assertNull(renderer.defaultFileExtension());
	}

	@Test
	public void testAnalysisFlowWithTimingReport() throws Exception {
		PMDRenderer renderer = new PMDRenderer();
		TimingReport timingReport = BDDMockito.mock(TimingReport.class);

		// Simulates PMD's engine delivering the final accumulated Report, replacing the PMD 6
		// start()/startFileAnalysis(DataSource)/end() lifecycle that no longer exists.
		Report report = Report.buildReport(listener -> {
		});
		renderer.outputReport(report);

		PMDReport pmdReport = renderer.createReport();
		pmdReport.logRuleBenchmarking();
		// test nothing happened with no timingreport
		Assertions.assertTrue(loggerRule.getMessages().isEmpty());

		renderer.addTimingReport(timingReport);
		pmdReport = renderer.createReport();
		pmdReport.logRuleBenchmarking();
		// test timing report exists
		List<String> messages = loggerRule.getMessages();
		Assertions.assertEquals(1, messages.size());
		Assertions.assertTrue(messages.get(0).contains("Wall Clock Time"));
	}

}
