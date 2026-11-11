package com.tracelink.appsec.module.regex.model;

import com.tracelink.appsec.watchtower.core.rule.RuleExecutionIdentity;
import com.tracelink.appsec.watchtower.core.rule.RulePriority;

import java.util.regex.Pattern;

/**
 * A simple interface to bring together the {@linkplain RegexCustomRuleDto} and
 * {@linkplain RegexProvidedRuleDto} classes
 *
 * @author Watchtower
 *
 */

public interface RegexRuleDto {
    RuleExecutionIdentity getExecutionIdentity();
    boolean isValidExtension(String fileName);
    Pattern getCompiledPattern();
    String getName();
    RulePriority getPriority();
    String getMessage();
}
