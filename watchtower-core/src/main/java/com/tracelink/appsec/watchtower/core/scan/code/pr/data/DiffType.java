package com.tracelink.appsec.watchtower.core.scan.code.pr.data;

/**
 * Denotes the diff status of a line
 *
 * @author csmith
 */
public enum DiffType {

    /**
     * If a Line was changed
     */
    MODIFIED,
    /**
     * If a line was untouched
     */
    EXISTING
}
