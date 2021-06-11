package com.tracelink.appsec.watchtower.cli;

import com.tracelink.appsec.watchtower.cli.executor.UploadScanExecutor;
import com.tracelink.appsec.watchtower.cli.executor.UploadScanParameters;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Command line interface for the Watchtower upload scan. Executes the scan via the {@link
 * UploadScanExecutor}.
 *
 * @author mcool
 */
public class WatchtowerCli {

	private static final Logger LOG = LoggerFactory.getLogger(WatchtowerCli.class);

	/**
	 * Main method to kick off the Watchtower upload scan
	 *
	 * @param args CLI arguments
	 */
	public static void main(String[] args) {
		try {
			UploadScanParameters params = new UploadScanParameters();
			if (!params.parseArgs(args)) {
				return;
			}
			UploadScanExecutor executor = new UploadScanExecutor(params);
			executor.executeUploadScan();
		} catch (Exception e) {
			LOG.error("An exception occurred while performing Watchtower upload scan", e);
		}
	}
}
