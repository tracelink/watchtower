package com.tracelink.appsec.watchtower.core.scan.processor;

import java.util.concurrent.Callable;

import com.tracelink.appsec.watchtower.core.report.ScanReport;

/**
 * Manages a single-threaded execution of regex scans. the processor will find files and for each
 * file do the actual scan, collect the file report, and add to the final report
 *
 * @author csmith
 */

public class SingleThreadedProcessor extends AbstractProcessor {

	public SingleThreadedProcessor(CallableCreator processor) {
		super(processor);
	}

	@Override
	protected void processFile(Callable<ScanReport> callable) {
		try {
			addReport(callable.call());
		} catch (Exception e) {
			addSystemException(e);
		}
	}

}
