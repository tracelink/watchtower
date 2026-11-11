package com.tracelink.appsec.watchtower.core.scan.apiintegration.webhook;
import java.util.List;
/** Only events supported by Watchtower can be selected for managed hooks. */
public enum BBWebhookPreset {
 SCAN_ONLY(List.of("pullrequest:created", "pullrequest:updated")),
 SCAN_AND_CLOSE(List.of("pullrequest:created", "pullrequest:updated", "pullrequest:fulfilled", "pullrequest:rejected")),
 ALL(List.of("pullrequest:created", "pullrequest:updated", "pullrequest:fulfilled", "pullrequest:rejected", "pullrequest:comment_created"));
 private final List<String> events;
 BBWebhookPreset(List<String> events) { this.events=events; }
 public List<String> events() { return events; }
}
