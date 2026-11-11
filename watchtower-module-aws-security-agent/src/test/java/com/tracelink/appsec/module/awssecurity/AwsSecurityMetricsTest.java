package com.tracelink.appsec.module.awssecurity;

import java.util.*;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;

class AwsSecurityMetricsTest {
    @Test void limitGaugeFollowsAnAdministratorChangeOnRefresh() {
        var runs = mock(AwsSecurityRunRepository.class);
        when(runs.operationalTotals()).thenReturn(List.of());
        when(runs.severityTotals()).thenReturn(List.of());
        when(runs.validationTotals()).thenReturn(List.of());
        var capacity = mock(AwsSecurityCapacity.class);
        when(capacity.deploymentDefault()).thenReturn(2);
        when(capacity.limit()).thenReturn(3);
        var registry = new SimpleMeterRegistry();
        var metrics = new AwsSecurityMetrics(runs, registry, capacity);

        assertEquals(2, registry.get("watchtower.aws.security.capacity.limit").gauge().value());
        metrics.refresh();
        assertEquals(3, registry.get("watchtower.aws.security.capacity.limit").gauge().value());
    }

    @Test void persistedTotalsSurviveRefreshAndUnknownLabelsDoNotCreateMetricCardinality() {
        var runs = mock(AwsSecurityRunRepository.class); var registry = new SimpleMeterRegistry(); var metrics = new AwsSecurityMetrics(runs, registry);
        var totals = mock(AwsSecurityRunRepository.Totals.class); when(totals.getStage()).thenReturn(AwsSecurityRun.Stage.COMPLETE); when(totals.getJobs()).thenReturn(1L);
        when(totals.getOmitted()).thenReturn(5L); when(totals.getThrottles()).thenReturn(2L); when(totals.getFailures()).thenReturn(3L);
        when(runs.operationalTotals()).thenReturn(List.of(totals)); when(runs.activePermitCount()).thenReturn(1L);
        when(runs.severityTotals()).thenReturn(List.of(count("CRITICAL", 4), count("FUTURE", 2)));
        when(runs.validationTotals()).thenReturn(List.of(count("PROVIDER_NEW_STATUS", 4)));
        metrics.refresh(); metrics.refresh();
        assertEquals(5, registry.get("watchtower.aws.security.omitted").gauge().value());
        assertEquals(2, registry.get("watchtower.aws.security.throttles").gauge().value());
        assertEquals(1, registry.get("watchtower.aws.security.capacity.used").gauge().value());
        assertEquals(4, registry.get("watchtower.aws.security.findings.severity").tag("severity", "CRITICAL").gauge().value());
        assertEquals(2, registry.get("watchtower.aws.security.findings.severity").tag("severity", "UNKNOWN").gauge().value());
        assertEquals(4, registry.get("watchtower.aws.security.findings.validation").tag("validation", "UNKNOWN").gauge().value());
        assertNull(registry.find("watchtower.aws.security.findings.validation").tag("validation", "PROVIDER_NEW_STATUS").gauge());
    }
    private AwsSecurityRunRepository.EvidenceCount count(String label, long findings) {
        return new AwsSecurityRunRepository.EvidenceCount() { public String getLabel() { return label; } public long getFindings() { return findings; } };
    }
}
