package com.tracelink.appsec.watchtower.core.metrics.bucketer;

import java.time.LocalDateTime;
import java.time.format.TextStyle;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Represents "buckets" of data that each span one day. A day represents the
 * time from midnight today (inclusive) until midnight on the following day
 * (exclusive).
 *
 * @author mcool
 */
public class DayIntervals extends BucketIntervals {

	public DayIntervals(LocalDateTime start, LocalDateTime end) {
		super(start == null ? null : start.toLocalDate().atStartOfDay(),
				end == null ? null : end.toLocalDate().atStartOfDay(), (d) -> d.plusDays(1));
	}

	@Override
	public List<String> getLabels() {
		List<String> labels = new ArrayList<>();

		LocalDateTime labelStart = getStart();
		while (labelStart.compareTo(getEnd()) < 0) {
			String dayOfWeek = labelStart.getDayOfWeek().getDisplayName(TextStyle.SHORT, Locale.US);
			labels.add(dayOfWeek);
			labelStart = labelStart.plusDays(1);
		}
		return labels;
	}
}
