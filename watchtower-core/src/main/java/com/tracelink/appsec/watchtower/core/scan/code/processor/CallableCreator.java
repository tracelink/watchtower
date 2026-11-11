package com.tracelink.appsec.watchtower.core.scan.code.processor;

import java.nio.file.Path;
import java.util.concurrent.Callable;

import com.tracelink.appsec.watchtower.core.ruleset.RulesetDto;
import com.tracelink.appsec.watchtower.core.scan.code.report.CodeScanReport;

/**
 * Interface to create a callable for a specific file in a scan
 * 
 * @author csmith
 *
 */
@FunctionalInterface
public interface CallableCreator {
	/**
	 * Given a file path and ruleset, generate a Callable for the processor to handle scanning the
	 * single file
	 * 
	 * @param file    a single file to scan
	 * @param ruleset a ruleset to use to scan
	 * @return a callable to be used to scan a single file with a set of rules
	 * @throws ProcessorSetupException if the callable can't be created
	 */
	Callable<CodeScanReport> createCallable(Path file, RulesetDto ruleset)
			throws ProcessorSetupException;
}
