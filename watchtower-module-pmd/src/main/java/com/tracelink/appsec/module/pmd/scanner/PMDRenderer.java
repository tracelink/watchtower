package com.tracelink.appsec.module.pmd.scanner;

import java.io.IOException;
import java.io.Writer;

import net.sourceforge.pmd.benchmark.TimingReport;
import net.sourceforge.pmd.renderers.AbstractAccumulatingRenderer;
import net.sourceforge.pmd.reporting.Report;

/**
 * PMD Reporter that collects the reports for use within the {@link PMDReport} scheme
 *
 * @author csmith
 */
public class PMDRenderer extends AbstractAccumulatingRenderer {

	private TimingReport timing;

	// Defaults to an empty (but non-null) Report so createReport() is always safe to call, even
	// if outputReport(Report) is never invoked (e.g. a scan with zero source files).
	private Report finalReport = Report.buildReport(listener -> {
	});

	public PMDRenderer() {
		super("PMDRenderer", "Renderer for the PMD WatchtowerModule");
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

	/**
	 * Called once with the fully accumulated {@link Report} for the whole analysis. Replaces the
	 * PMD 6 {@code start()}/{@code end()} lifecycle, which no longer exists on
	 * {@link AbstractAccumulatingRenderer} in PMD 7.
	 */
	@Override
	protected void outputReport(Report report) throws IOException {
		this.finalReport = report;
	}

	/**
	 * @return a report using this report's data and the PMD benchmark, if used
	 */
	public PMDReport createReport() {
		return new PMDReport(finalReport, timing);
	}

	/**
	 * @param timing if we used the PMD benchmarker, add it
	 */
	public void addTimingReport(TimingReport timing) {
		this.timing = timing;
	}
}
