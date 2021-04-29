package com.tracelink.appsec.watchtower.core.scan.processor;

import java.io.IOException;
import java.nio.file.FileVisitResult;
import java.nio.file.FileVisitor;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;

import com.tracelink.appsec.watchtower.core.report.ScanReport;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetDto;

/**
 * the processor handles scanning all files in a directory
 *
 * @author csmith
 */
public abstract class AbstractProcessor {
	private CallableCreator processor;
	private List<ScanReport> reports = new ArrayList<ScanReport>();
	private List<String> systemExceptions = new ArrayList<String>();

	public AbstractProcessor(CallableCreator processor) {
		this.processor = processor;
	}

	/**
	 * Execute the scan given the ruleset and top level directory path
	 * 
	 * @param ruleset      The set of rules for this scan
	 * @param startingPath the top level directory containing the scanning contents
	 */
	public void runScan(final RulesetDto ruleset, Path startingPath) {
		try {
			Files.walkFileTree(startingPath, new FileVisitor<Path>() {

				@Override
				public FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes attrs)
						throws IOException {
					return FileVisitResult.CONTINUE;
				}

				@Override
				public FileVisitResult visitFile(Path file, BasicFileAttributes attrs)
						throws IOException {
					if (attrs.isRegularFile()) {
						try {
							processFile(processor.createCallable(file, ruleset));
						} catch (ProcessorSetupException e) {
							throw new IOException(e);
						}
					}
					return FileVisitResult.CONTINUE;
				}

				@Override
				public FileVisitResult visitFileFailed(Path file, IOException exc)
						throws IOException {
					addSystemException(exc);
					return FileVisitResult.CONTINUE;
				}

				@Override
				public FileVisitResult postVisitDirectory(Path dir, IOException exc)
						throws IOException {
					return FileVisitResult.CONTINUE;
				}
			});
		} catch (IOException e) {
			addSystemException(e);
		}
	}

	/**
	 * Capture an exception during processing in order to report on it later
	 * 
	 * @param t the Throwable to log
	 */
	protected void addSystemException(Throwable t) {
		systemExceptions.add("Exception: " + t.getMessage());
	}

	/**
	 * Add the report from one of the processing threads to be used later
	 * 
	 * @param report a report of a single file from a processing thread
	 */
	protected void addReport(ScanReport report) {
		reports.add(report);
	}

	public List<ScanReport> getReports() {
		return this.reports;
	}

	public List<String> getSystemExceptions() {
		return this.systemExceptions;
	}

	/**
	 * for a given file, run the processor scan on the file
	 *
	 * @param callable the scan to run
	 */
	protected abstract void processFile(Callable<ScanReport> callable);

}
