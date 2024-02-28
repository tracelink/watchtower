package com.tracelink.appsec.watchtower.core.metrics.bucketer;

/**
 * Enum representing standard time periods over which to bucket items. Used by the {@link
 * BucketIntervals} and the {@link StandardIntervalBucketer} to correctly bucket items in
 * appropriate time periods.
 *
 * @author mcool
 */
public enum BucketerTimePeriod {
	LAST_WEEK("last-week"), LAST_FOUR_WEEKS("last-four-weeks"), LAST_SIX_MONTHS(
			"last-six-months"),LAST_YEAR("last-year"), ALL_TIME("all-time");

	private final String period;

	BucketerTimePeriod(String period) {
		this.period = period;
	}

	public String getPeriod() {
		return period;
	}

	/**
	 * Gets the {@link BucketerTimePeriod} associated with the given period string. Throws an
	 * {@link IllegalArgumentException} if there is no {@link BucketerTimePeriod} for the given
	 * period.
	 *
	 * @param period string representation of an {@link BucketerTimePeriod}
	 * @return the associated {@link BucketerTimePeriod}
	 */
	public static BucketerTimePeriod ofPeriod(String period) {
		for (BucketerTimePeriod timePeriod : BucketerTimePeriod.values()) {
			if (timePeriod.getPeriod().equals(period)) {
				return timePeriod;
			}
		}
		throw new IllegalArgumentException("Unknown time period");
	}
}
