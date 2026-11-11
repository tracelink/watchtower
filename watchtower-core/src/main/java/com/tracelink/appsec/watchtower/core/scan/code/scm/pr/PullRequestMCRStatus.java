package com.tracelink.appsec.watchtower.core.scan.code.scm.pr;

import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;

/**
 * The status of a manual code review
 *
 * @author droseen
 *
 */
public enum PullRequestMCRStatus {
    // The order is stored (as the ordinal), so new values go at the end.
    NOT_APPLICABLE("Not Applicable", "block", "neutral", "No manual review is needed for this pull request."),
    PENDING_REVIEW("Pending Review", "hourglass_top", "warning", "Waiting for a reviewer to start."),
    IN_PROGRESS("In Progress", "edit_note", "info", "A reviewer is looking at the matches."),
    REVIEWED("Reviewed", "task_alt", "success", "A reviewer went through the matches."),
    RECOMMENDATIONS("Reviewed w/ Recommendations", "rate_review", "success",
            "A reviewer went through the matches and left recommendations.");

    private final String displayName;
    private final String icon;
    private final String tone;
    private final String meaning;

    PullRequestMCRStatus(String name, String icon, String tone, String meaning) {
        this.displayName = name;
        this.icon = icon;
        this.tone = tone;
        this.meaning = meaning;
    }

    public String getDisplayName() {
        return this.displayName;
    }

    /** The Material icon shown on the status chip. */
    public String getIcon() {
        return this.icon;
    }

    /** The colour of the status chip: neutral, warning, info or success. */
    public String getTone() {
        return this.tone;
    }

    /** What the status means, shown when the chip is hovered. */
    public String getMeaning() {
        return this.meaning;
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

    /**
     * Converts a {@linkplain PullRequestMCRStatus} to/from its ordinal, stored as a String, to
     * support saving to the {@code mcr_status} varchar column. Hibernate's implicit ordinal
     * mapping is deliberately not used here since it now binds/extracts via a numeric JDBC type
     * (e.g. TINYINT) rather than String, which does not match this column's actual type.
     */
    @Converter
    public static class PullRequestMCRStatusConverter
            implements AttributeConverter<PullRequestMCRStatus, String> {

        @Override
        public String convertToDatabaseColumn(PullRequestMCRStatus attribute) {
            return attribute == null ? null : String.valueOf(attribute.ordinal());
        }

        @Override
        public PullRequestMCRStatus convertToEntityAttribute(String dbData) {
            if (dbData == null) {
                return null;
            }
            return PullRequestMCRStatus.values()[Integer.parseInt(dbData)];
        }

    }

}
