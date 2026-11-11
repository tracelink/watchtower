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

import net.sourceforge.pmd.benchmark.TextTimingReportRenderer;
import net.sourceforge.pmd.benchmark.TimingReport;
import net.sourceforge.pmd.benchmark.TimingReportRenderer;
import net.sourceforge.pmd.lang.rule.Rule;
import net.sourceforge.pmd.reporting.Report;

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

		report.getProcessingErrors().forEach(e -> addError(new CodeScanError(
				"In File '" + e.getFileId().getAbsolutePath() + "' Error: " + e.getMsg())));
		report.getConfigurationErrors().forEach(e -> {
			addError(new CodeScanError("Poorly Configured Rule. Reason: " + e.issue()));
			// PMD dropped just this rule and carried on with the rest, so only this rule did not run.
			if (e.rule() != null) {
				addFailedRule(e.rule().getName(), e.issue());
			}
		});
		// When the only problems are rules PMD dropped, the scanner itself ran: say so, and let the rules named above
		// carry the failure. A file that could not be processed, or a problem with no rule to name, still fails the scanner.
		if (report.getProcessingErrors().isEmpty() && !report.getConfigurationErrors().isEmpty()
				&& report.getConfigurationErrors().stream().allMatch(e -> e.rule() != null)) {
			setExecutionStatus("RAN");
		}
		report.getViolations().forEach(v -> {
			Rule pmdRule = v.getRule();

			CodeScanViolation sv = new CodeScanViolation();
			sv.setViolationName(pmdRule.getName());
			sv.setFileName(v.getFileId().getAbsolutePath().trim());
			sv.setLineNum(v.getBeginLine());
			sv.setSeverity(convertPriority(pmdRule.getPriority()));
			sv.setMessage(v.getDescription().trim());
			addViolation(sv);
		});
	}

	private RulePriority convertPriority(net.sourceforge.pmd.lang.rule.RulePriority pmdPriority) {
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
			default:
				throw new IllegalArgumentException("Unknown conversion for pmd rule priority");
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
