package com.tracelink.appsec.module.pmd.scanner;

import java.io.IOException;
import java.io.Writer;

import net.sourceforge.pmd.benchmark.TimingReport;
import net.sourceforge.pmd.renderers.AbstractAccumulatingRenderer;

/**
 * PMD Reporter that collects the reports for use within the {@link PMDReport} scheme
 *
 * @author csmith
 */
public class PMDRenderer extends AbstractAccumulatingRenderer {

	private TimingReport timing;

	public PMDRenderer() {
		super("PMDRenderer", "Renderer for the PMD WatchtowerModule");
	}

	@Override
	public void start() throws IOException {
		super.start();
		report.start();
	}

	/**
	 * Writer will be forced to a Noop Writer
	 */
	@Override
	public void setWriter(Writer writer) {
		try {
			// in case someone sent in a real writer, we're ignoring it
			writer.close();
		} catch (IOException e) {
			// ignore close exception
		}
		super.setWriter(new NoopWriter());
	}

	@Override
	public String defaultFileExtension() {
		return null;
	}

	@Override
	public void end() throws IOException {
		report.end();
		// do nothing else. use createReport to get the report object
	}

	/**
	 * @return a report using this report's data and the PMD benchmark, if used
	 */
	public PMDReport createReport() {
		return new PMDReport(report, timing);
	}

	/**
	 * @param timing if we used the PMD benchmarker, add it
	 */
	public void addTimingReport(TimingReport timing) {
		this.timing = timing;
	}
}
