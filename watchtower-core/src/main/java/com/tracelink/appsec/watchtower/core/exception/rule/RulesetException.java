package com.tracelink.appsec.watchtower.core.exception.rule;

import com.tracelink.appsec.watchtower.core.ruleset.RulesetEntity;

/**
 * Exception thrown when an illegal action is attempted on a {@link RulesetEntity}.
 *
 * @author mcool
 */
public class RulesetException extends Exception {

    private static final long serialVersionUID = -4739411865229553870L;

    public RulesetException(String message) {
        super(message);
    }
}
