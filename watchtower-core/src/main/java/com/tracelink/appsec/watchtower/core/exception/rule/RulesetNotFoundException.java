package com.tracelink.appsec.watchtower.core.exception.rule;

import com.tracelink.appsec.watchtower.core.ruleset.RulesetEntity;

/**
 * Exception thrown when a {@link RulesetEntity} cannot be found in the database with a matching ID or name.
 *
 * @author mcool
 */
public class RulesetNotFoundException extends Exception {
    private static final long serialVersionUID = 4333411577752771995L;

    public RulesetNotFoundException(String message) {
        super(message);
    }
}
