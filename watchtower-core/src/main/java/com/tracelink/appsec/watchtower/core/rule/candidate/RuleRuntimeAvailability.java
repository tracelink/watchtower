package com.tracelink.appsec.watchtower.core.rule.candidate;

/** Module-owned availability checks before queued tests or approving old evidence. */
public interface RuleRuntimeAvailability {
 String module();
 boolean available();
 /** Fresh module-owned runtime evidence included in reviewed-test approval identity. */
 String executionIdentity();
}
