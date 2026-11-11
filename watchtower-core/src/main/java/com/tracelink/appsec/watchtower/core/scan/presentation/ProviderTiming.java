package com.tracelink.appsec.watchtower.core.scan.presentation;

import java.util.List;
import com.tracelink.appsec.watchtower.core.scan.code.report.ProviderAssessmentReference;

/**
 * The time a remote provider (the AWS review) kept a scan open after Watchtower's own scanners finished. A scan's local end
 * is when its local result was saved; the AWS review starts after that and runs for minutes, so durations that stop at the
 * local end understate how long the scan really took. One place decides how that wait is added, so every duration agrees.
 *
 * <p>The wait is the latest provider finish after the local end, not a sum: providers run side by side, and a provider that
 * ended before the local scan adds nothing. A provider still running makes the whole scan "pending": no final time exists.
 */
public final class ProviderTiming {
    public static final ProviderTiming NONE = new ProviderTiming(0, false);

    private final long extraMs;
    private final boolean pending;

    private ProviderTiming(long extraMs, boolean pending) {
        this.extraMs = extraMs;
        this.pending = pending;
    }

    /** Timing for a scan whose local result was saved at {@code localEndMillis}. Providers without recorded times add nothing. */
    public static ProviderTiming of(long localEndMillis, List<ProviderAssessmentReference> providers) {
        if (providers == null || providers.isEmpty() || localEndMillis <= 0) return NONE;
        long extra = 0;
        boolean pending = false;
        for (ProviderAssessmentReference provider : providers) {
            var status = provider.status();
            if (status == null || status.startedAt() == null) continue;
            Long finished = status.finishedAt();
            if (finished == null) {
                pending |= !status.finished();
                continue;
            }
            extra = Math.max(extra, finished - localEndMillis);
        }
        return extra == 0 && !pending ? NONE : new ProviderTiming(extra, pending);
    }

    /** Same, for rows whose provider JSON may be unreadable: those simply show the local time. */
    public static ProviderTiming ofJson(long localEndMillis, String providerSummaryJson) {
        try {
            return of(localEndMillis, ProviderAssessmentReference.decode(providerSummaryJson));
        } catch (IllegalArgumentException unreadable) {
            return NONE;
        }
    }

    /** Milliseconds to add to the local duration; zero while a provider is still running. */
    public long extraMs() { return pending ? 0 : extraMs; }

    /** True while a provider is still running, so the scan has no final time yet. */
    public boolean pending() { return pending; }

    /** When the scan really finished: the local end plus the provider wait. */
    public long effectiveEnd(long localEndMillis) { return localEndMillis + extraMs(); }

    /** The list format of the whole scan's duration ("Running" while a provider is still working). */
    public String duration(long startMillis, long localEndMillis) {
        return pending ? "Running" : HomeActivityItem.formatDuration(startMillis, effectiveEnd(localEndMillis));
    }
}
