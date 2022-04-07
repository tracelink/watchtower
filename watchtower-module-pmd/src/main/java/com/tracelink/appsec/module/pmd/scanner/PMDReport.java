package com.tracelink.appsec.module.pmd.scanner;

import java.io.IOException;
import java.io.StringWriter;
import java.io.Writer;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.tracelink.appsec.watchtower.core.rule.RulePriority;
import com.tracelink.appsec.watchtower.core.scan.code.report.CodeScanError;
import com.tracelink.appsec.watchtower.core.scan.code.report.CodeScanReport;
import com.tracelink.appsec.watchtower.core.scan.code.report.CodeScanViolation;

import net.sourceforge.pmd.Report;
import net.sourceforge.pmd.Rule;
import net.sourceforge.pmd.benchmark.TextTimingReportRenderer;
import net.sourceforge.pmd.benchmark.TimingReport;
import net.sourceforge.pmd.benchmark.TimingReportRenderer;

/**
 * Translation from PMD to {@link CodeScanReport}
 *
 * @author csmith, mcool
 */
public class PMDReport extends CodeScanReport {
	private static final Logger LOG = LoggerFactory.getLogger(PMDReport.class);
	private final TimingReport timingReport;

	public PMDReport(Report report, TimingReport timingReport) {
		super();
		this.timingReport = timingReport;

		if (report.hasErrors()) {
			report.errors().forEachRemaining(e -> addError(
					new CodeScanError("In File '" + e.getFile() + "' Error: " + e.getMsg())));
		}
		if (report.hasConfigErrors()) {
			report.configErrors().forEachRemaining(
					e -> addError(
							new CodeScanError("Poorly Configured Rule. Reason: " + e.issue())));
		}
		if (report.iterator().hasNext()) {
			report.iterator().forEachRemaining(v -> {
				Rule pmdRule = v.getRule();

				CodeScanViolation sv = new CodeScanViolation();
				sv.setViolationName(pmdRule.getName());
				sv.setFileName(v.getFilename().trim());
				sv.setLineNum(v.getBeginLine());
				sv.setSeverity(convertPriority(pmdRule.getPriority()));
				sv.setMessage(v.getDescription().trim());
				addViolation(sv);
			});
		}
	}

	private RulePriority convertPriority(net.sourceforge.pmd.RulePriority pmdPriority) {
		switch (pmdPriority) {
			case HIGH:
				return RulePriority.HIGH;
			case MEDIUM_HIGH:
				return RulePriority.MEDIUM_HIGH;
			case MEDIUM:
				return RulePriority.MEDIUM;
			case MEDIUM_LOW:
				return RulePriority.MEDIUM_LOW;
			case LOW:
				return RulePriority.LOW;
		}
		throw new IllegalArgumentException("Unknown conversion for pmd rule priority");
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
