package com.tracelink.appsec.watchtower.core.scan.code.scm.api;

/** Limits enforced during transfer and extraction, rather than after the source fills disk. */
public record SourceDownloadLimits(long archiveBytes, long extractedBytes, int entries) {
    public static final SourceDownloadLimits SCAN = new SourceDownloadLimits(512L * 1024 * 1024, 2L * 1024 * 1024 * 1024, 100_000);
    public static final SourceDownloadLimits ASSISTANT = new SourceDownloadLimits(64L * 1024 * 1024, 256L * 1024 * 1024, 10_000);
    public SourceDownloadLimits {
        if (archiveBytes <= 0 || extractedBytes <= 0 || entries <= 0) throw new IllegalArgumentException("Invalid source limits");
    }
}
