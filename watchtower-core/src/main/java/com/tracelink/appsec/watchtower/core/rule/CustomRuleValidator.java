package com.tracelink.appsec.watchtower.core.rule;

/**
 * Lets a module check its own rules beyond bean validation before they are saved by a ruleset
 * import - for example that a custom secrets rule compiles in the scanner and matches its
 * samples. The module's own designer and editor apply the same check; this keeps an import from
 * becoming a way around it. Register an implementation as a Spring bean.
 *
 * @author Watchtower
 */
public interface CustomRuleValidator {

	/**
	 * @param rule an incoming rule
	 * @return true if this validator owns the rule's type
	 */
	boolean supports(RuleDto rule);

	/**
	 * @param rule an incoming rule this validator supports
	 * @throws RuleException with a user-facing reason if the rule must not be saved
	 */
	void validate(RuleDto rule) throws RuleException;
}
