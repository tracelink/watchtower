package com.tracelink.appsec.watchtower.core.metrics.bucketer;

import java.time.LocalDateTime;
import java.time.Month;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;

/**
 * Represents "buckets" of data that each span one month. A month represents the
 * time from the first day of the month to the last day of the month, inclusive.
 *
 * @author mcool
 */
public class MonthIntervals extends BucketIntervals {

	private final DateTimeFormatter dtf1 = DateTimeFormatter.ofPattern("MMM yyyy");
	private final DateTimeFormatter dtf2 = DateTimeFormatter.ofPattern("MMM");

	public MonthIntervals(LocalDateTime start, LocalDateTime end) {
		super(start == null ? null : start.toLocalDate().atStartOfDay(),
				end == null ? null : end.toLocalDate().atStartOfDay(), (d) -> d.plusMonths(1));
	}

	@Override
	public List<String> getLabels() {
		List<String> labels = new ArrayList<>();

		LocalDateTime labelStart = getStart();
		LocalDateTime labelEnd = getEnd().minusDays(1);
		while (labelStart.compareTo(labelEnd) <= 0) {
			String label;
			// If month is December or January, format as "MMM yyyy"
			if (labelStart.getMonth().equals(Month.DECEMBER) || labelStart.getMonth()
					.equals(Month.JANUARY)) {
				label = labelStart.format(dtf1);
			} else {
				// Format as "MMM"
				label = labelStart.format(dtf2);
			}
			labels.add(label);
			labelStart = labelStart.plusMonths(1);
		}
		return labels;
	}
}
