package com.tracelink.appsec.watchtower.core.alerting;

import com.tracelink.appsec.watchtower.core.rule.RulePriority;

/**
 * One thing an alert reports, e.g. one secrets finding. Its text is what the channel shows, so
 * callers must never put a secret in it.
 *
 * @param dedupeKey identifies the item across raises, e.g. a hash of PR, rule, file and line
 * @param priority  its rule priority, or null if it has none
 * @param text      one line describing it
 * @author Watchtower
 */
public record AlertItem(String dedupeKey, RulePriority priority, String text) {
}
