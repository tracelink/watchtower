package com.tracelink.appsec.watchtower.cli.reporter;

import com.tracelink.appsec.watchtower.cli.scan.UploadScanResult;
import java.time.Duration;
import java.util.Collections;
import org.slf4j.Logger;

/**
 * Abstract class to report Watchtower scan results in various formats. Reports a summary of the
 * scan results to the console.
 *
 * @author mcool
 */
public abstract class AbstractReporter {

	private final Logger log;

	public AbstractReporter(Logger log) {
		this.log = log;
	}

	/**
	 * Reports a summary of the given scan results to the console.
	 *
	 * @param scanResult the scan results to report a summary for
	 */
	public final void reportSummary(UploadScanResult scanResult) {
		if (scanResult == null) {
			return;
		}
		Duration scanDuration = Duration
				.between(scanResult.getSubmitDate(), scanResult.getEndDate());
		int minutes = (int) (scanDuration.getSeconds() / 60);
		int secs = (int) (scanDuration.getSeconds() % 60);
		log.info(fill(80));
		log.info("Scan Report Summary");
		log.info(fill(80));
		log.info("Name:           " + scanResult.getName());
		log.info("Status:         " + scanResult.getStatus());
		log.info("Ticket:         " + scanResult.getTicket());
		log.info("Submitted By:   " + scanResult.getSubmittedBy());
		log.info("Submitted Date: " + scanResult.getSubmitDate());
		log.info("End Date:       " + scanResult.getEndDate());
		log.info("Scan Duration:  " + minutes + " minutes, " + secs + " seconds");
		log.info("Ruleset:        " + scanResult.getRuleset());
		log.info("Num Violations: " + scanResult.getViolationsFound());
		log.info(fill(80));
	}

	/**
	 * Reports details of the given scan results, including all violations found or errors from the
	 * Watchtower scan.
	 *
	 * @param scanResult the scan result to report
	 */
	public abstract void report(UploadScanResult scanResult);

	/**
	 * Returns a line of dashes with the given length to act as a visual marker for console output
	 *
	 * @param amount number of dashes to include
	 * @return the dashes line
	 */
	protected String fill(int amount) {
		return String.join("", Collections.nCopies(amount, "-"));
	}
}
