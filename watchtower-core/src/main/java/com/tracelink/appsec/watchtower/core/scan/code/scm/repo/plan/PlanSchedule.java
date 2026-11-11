package com.tracelink.appsec.watchtower.core.scan.code.scm.repo.plan;

import java.time.DayOfWeek;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.temporal.ChronoUnit;
import java.time.temporal.TemporalAdjusters;

import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.entity.PlanFrequency;

/**
 * When a recurring plan runs next: daily at an hour, weekly on a day (1 = Monday) at an hour,
 * or monthly on a day (1-28, so every month has it) at an hour.
 *
 * @author Watchtower
 */
public final class PlanSchedule {

	private PlanSchedule() {
	}

	/**
	 * @param frequency how often
	 * @param hour      0-23
	 * @param day       day of week (1-7) for weekly, day of month (1-28) for monthly
	 * @throws IllegalArgumentException if a value is out of range for the frequency
	 */
	public static void validate(PlanFrequency frequency, Integer hour, Integer day) {
		if (!frequency.isRecurring()) {
			return;
		}
		if (hour == null || hour < 0 || hour > 23) {
			throw new IllegalArgumentException("Choose an hour from 0 to 23");
		}
		if (frequency == PlanFrequency.WEEKLY && (day == null || day < 1 || day > 7)) {
			throw new IllegalArgumentException("Choose a day of the week");
		}
		if (frequency == PlanFrequency.MONTHLY && (day == null || day < 1 || day > 28)) {
			throw new IllegalArgumentException("Choose a day of the month from 1 to 28");
		}
	}

	/**
	 * @param frequency how often
	 * @param hour      the hour of day
	 * @param day       the day, as for {@link #validate}
	 * @param after     epoch millis; the result is strictly later
	 * @param zone      the zone the hour and day are in
	 * @return epoch millis of the next run, or null for a plan that does not recur
	 */
	public static Long next(PlanFrequency frequency, Integer hour, Integer day, long after,
			ZoneId zone) {
		if (!frequency.isRecurring()) {
			return null;
		}
		ZonedDateTime from = Instant.ofEpochMilli(after).atZone(zone);
		ZonedDateTime candidate = from.truncatedTo(ChronoUnit.DAYS).withHour(hour);
		if (frequency == PlanFrequency.WEEKLY) {
			candidate = candidate.with(TemporalAdjusters.nextOrSame(DayOfWeek.of(day)));
		} else if (frequency == PlanFrequency.MONTHLY) {
			candidate = candidate.withDayOfMonth(day);
		}
		while (!candidate.isAfter(from)) {
			if (frequency == PlanFrequency.WEEKLY) {
				candidate = candidate.plusWeeks(1);
			} else if (frequency == PlanFrequency.MONTHLY) {
				candidate = candidate.plusMonths(1);
			} else {
				candidate = candidate.plusDays(1);
			}
		}
		return candidate.toInstant().toEpochMilli();
	}
}
