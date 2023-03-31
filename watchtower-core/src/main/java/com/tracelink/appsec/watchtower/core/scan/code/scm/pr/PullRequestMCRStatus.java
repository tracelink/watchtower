package com.tracelink.appsec.watchtower.core.scan.code.scm.pr;

/**
 * The status of a manual code review
 *
 * @author droseen
 *
 */
public enum PullRequestMCRStatus {
    NOT_APPLICABLE("Not Applicable"),
    PENDING_REVIEW("Pending Review"),
    IN_PROGRESS("In Progress"),
    REVIEWED("Reviewed"),
    RECOMMENDATIONS("Reviewed w/ Recommendations");

    private final String displayName;

    PullRequestMCRStatus(String name) {
        this.displayName = name;
    }

    public String getDisplayName() {
        return this.displayName;
    }

    /**
     * Convert a String representation of an MCR scan status enum to a {@linkplain PullRequestMCRStatus}
     *
     * @param enumString the display name of a {@linkplain PullRequestMCRStatus}
     * @return the enum value that matches the input, or null if not found
     */
    public static PullRequestMCRStatus enumStringToStatus(String enumString) {
        for (PullRequestMCRStatus status: PullRequestMCRStatus.values()) {
            if (status.toString().equals(enumString)) {
                return status;
            }
        }
        return null;
    }

}
