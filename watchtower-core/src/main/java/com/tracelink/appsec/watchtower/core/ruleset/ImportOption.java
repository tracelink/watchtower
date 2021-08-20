package com.tracelink.appsec.watchtower.core.ruleset;

/**
 * The option used during import to dictate how the import should handle merging rules or rulesets
 * 
 * @author csmith
 *
 */
public enum ImportOption {
	/**
	 * Skip all import steps for this option
	 */
	SKIP,
	/**
	 * If the import object is a ruleset and...
	 * <p>
	 * --is provided, update the blocking level and description
	 * <p>
	 * --is not provided, update the blocking level, description, and designation
	 * <p>
	 * If the import object is a rule and...
	 * <p>
	 * --is provided, update the priority
	 * <p>
	 * --is not provided, update all data
	 */
	UPDATE,
	/**
	 * If the import object is a ruleset and...
	 * <p>
	 * --is provided, update the blocking level and description
	 * <p>
	 * --is not provided, update the blocking level, description, and designation
	 * <p>
	 * If the import object is a rule and...
	 * <p>
	 * --is provided, update all data, but keep the existing priority
	 * <p>
	 * --is not provided, update all data
	 */
	OVERRIDE;

}
