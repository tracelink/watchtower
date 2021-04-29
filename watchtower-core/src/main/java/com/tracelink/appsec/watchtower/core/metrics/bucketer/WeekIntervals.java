package com.tracelink.appsec.watchtower.core.metrics.bucketer;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;

/**
 * Represents "buckets" of data that each span one week. A week represents the
 * past 7 days from the current date, i.e. if today is Wednesday, the week is
 * from the last Thursday at midnight (inclusive) to tomorrow at midnight
 * (exclusive).
 *
 * @author mcool
 */
public class WeekIntervals extends BucketIntervals {

	private final DateTimeFormatter dtf1 = DateTimeFormatter.ofPattern("MMM dd");
	private final DateTimeFormatter dtf2 = DateTimeFormatter.ofPattern("dd");

	public WeekIntervals(LocalDateTime start, LocalDateTime end) {
		super(start == null ? null : start.toLocalDate().atStartOfDay(),
				end == null ? null : end.toLocalDate().atStartOfDay(), (d) -> d.plusWeeks(1));
	}

	@Override
	public List<String> getLabels() {
		List<String> labels = new ArrayList<>();

		LocalDateTime labelStart = getStart();
		LocalDateTime labelEnd = getEnd().minusDays(1);
		while (labelStart.compareTo(labelEnd) < 0) {
			String label;
			// Get the local date that represents the end of this week
			LocalDateTime weekEnd = labelStart.plusDays(6);
			// If the week starts and ends in different months, format as "MMM dd - MMM dd"
			if (labelStart.getMonth().compareTo(weekEnd.getMonth()) != 0) {
				label = labelStart.format(dtf1) + " - " + weekEnd.format(dtf1);
			} else {
				// Format week as "MMM dd - dd"
				label = labelStart.format(dtf1) + " - " + weekEnd.format(dtf2);
			}

			labels.add(label);
			labelStart = labelStart.plusWeeks(1);
		}
		return labels;
	}
}
