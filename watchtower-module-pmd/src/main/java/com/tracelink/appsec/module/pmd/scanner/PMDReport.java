package com.tracelink.appsec.module.pmd.scanner;

import java.io.IOException;
import java.io.StringWriter;
import java.io.Writer;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.tracelink.appsec.watchtower.core.report.ScanError;
import com.tracelink.appsec.watchtower.core.report.ScanReport;
import com.tracelink.appsec.watchtower.core.report.ScanViolation;

import net.sourceforge.pmd.Report;
import net.sourceforge.pmd.Rule;
import net.sourceforge.pmd.benchmark.TextTimingReportRenderer;
import net.sourceforge.pmd.benchmark.TimingReport;
import net.sourceforge.pmd.benchmark.TimingReportRenderer;

/**
 * Translation from PMD to {@link ScanReport}
 *
 * @author csmith, mcool
 */
public class PMDReport extends ScanReport {
	private static final Logger LOG = LoggerFactory.getLogger(PMDReport.class);
	private final TimingReport timingReport;

	public PMDReport(Report report, TimingReport timingReport) {
		super();
		this.timingReport = timingReport;

		if (report.hasErrors()) {
			report.errors().forEachRemaining(e -> addError(
					new ScanError("In File '" + e.getFile() + "' Error: " + e.getMsg())));
		}
		if (report.hasConfigErrors()) {
			report.configErrors().forEachRemaining(
					e -> addError(new ScanError("Poorly Configured Rule. Reason: " + e.issue())));
		}
		if (report.iterator().hasNext()) {
			report.iterator().forEachRemaining(v -> {
				Rule pmdRule = v.getRule();

				ScanViolation sv = new ScanViolation();
				sv.setViolationName(pmdRule.getName());
				sv.setFileName(v.getFilename().trim());
				sv.setLineNum(v.getBeginLine());
				sv.setSeverity(pmdRule.getPriority().getName());
				sv.setSeverityValue(pmdRule.getPriority().getPriority());
				sv.setMessage(v.getDescription().trim());
				addViolation(sv);
			});
		}
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void logRuleBenchmarking() {
		if (timingReport != null) {
			final TimingReportRenderer renderer = new TextTimingReportRenderer();
			try {
				final Writer writer = new StringWriter();
				renderer.render(timingReport, writer);
				LOG.info("\n" + writer.toString());
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
	}
}
