package com.tracelink.appsec.watchtower.core.sidebar;

/**
 * A navigable ancestor in the page breadcrumb trail.
 *
 * @param label user-facing navigation label
 * @param url application-relative destination
 */
public record BreadcrumbLink(String label, String url) {
}
