package com.tracelink.appsec.watchtower.core.metrics.bucketer;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.TextStyle;
import java.util.List;
import java.util.Locale;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class BucketIntervalsTest {

	@Test
	public void testMonthIntervals() {
		LocalDateTime start = LocalDateTime.of(2020, 7, 12, 0, 0, 0).minusMonths(1);
		LocalDateTime end = start.plusWeeks(2);
		DateTimeFormatter formatter = DateTimeFormatter.ofPattern("MMM");
		MonthIntervals monthIntervals = new MonthIntervals(start, end);
		List<String> labels = monthIntervals.getLabels();
		Assertions.assertEquals(1, labels.size());
		Assertions.assertTrue(labels.get(0).contains(formatter.format(start)));

		monthIntervals = new MonthIntervals(LocalDateTime.of(2019, 12, 2, 0, 0, 0),
				LocalDateTime.of(2020, 1, 5, 0, 0, 0));
		labels = monthIntervals.getLabels();
		Assertions.assertEquals(2, labels.size());
		Assertions.assertEquals("Dec 2019", labels.get(0));
		Assertions.assertEquals("Jan 2020", labels.get(1));
	}

	@Test
	public void testWeekIntervals() {
		LocalDateTime start = LocalDateTime.now().minusWeeks(1);
		LocalDateTime end = LocalDateTime.now();
		DateTimeFormatter formatter = DateTimeFormatter.ofPattern("MMM dd");
		WeekIntervals weekIntervals = new WeekIntervals(start, end);
		List<String> labels = weekIntervals.getLabels();
		Assertions.assertEquals(1, labels.size());
		Assertions.assertTrue(labels.get(0).contains(formatter.format(start)));

		weekIntervals = new WeekIntervals(LocalDateTime.of(2019, 12, 29, 0, 0, 0),
				LocalDateTime.of(2020, 1, 5, 0, 0, 0));
		labels = weekIntervals.getLabels();
		Assertions.assertEquals(1, labels.size());
		Assertions.assertEquals("Dec 29 - Jan 04", labels.get(0));
	}

	@Test
	public void testDayIntervals() {
		LocalDateTime start = LocalDate.now().minusDays(1).atStartOfDay();
		LocalDateTime end = LocalDate.now().atStartOfDay();
		DayIntervals dayIntervals = new DayIntervals(start, end);
		List<String> labels = dayIntervals.getLabels();
		Assertions.assertEquals(1, labels.size());
		Assertions.assertEquals(start.getDayOfWeek().getDisplayName(TextStyle.SHORT, Locale.US),
				labels.get(0));

		dayIntervals = new DayIntervals(LocalDateTime.of(2019, 12, 29, 0, 0, 0),
				LocalDateTime.of(2020, 1, 1, 0, 0, 0));
		labels = dayIntervals.getLabels();
		Assertions.assertEquals(3, labels.size());
		Assertions.assertTrue(labels.contains("Sun"));
		Assertions.assertTrue(labels.contains("Mon"));
		Assertions.assertTrue(labels.contains("Tue"));
	}

	@Test
	public void TestBucketIntervalsNullArguments() {
		Assertions.assertThrows(IllegalArgumentException.class,
				() -> new MonthIntervals(null, LocalDateTime.now().minusWeeks(1)));
	}

	@Test
	public void TestBucketIntervalsStartAfterEnd() {
		Assertions.assertThrows(IllegalArgumentException.class,
				() -> new MonthIntervals(LocalDateTime.now(), LocalDateTime.now().minusWeeks(1)));
	}

	@Test
	public void testGetStart() {
		LocalDateTime start = LocalDateTime.now();
		MonthIntervals monthIntervals = new MonthIntervals(start, LocalDateTime.now().plusYears(1));
		Assertions.assertEquals(start.toLocalDate().atStartOfDay(), monthIntervals.getStart());
	}

	@Test
	public void testGetEnd() {
		LocalDateTime end = LocalDateTime.now();
		WeekIntervals weekIntervals = new WeekIntervals(LocalDateTime.now().minusYears(1), end);
		Assertions.assertEquals(end.toLocalDate().atStartOfDay(), weekIntervals.getEnd());
	}

	@Test
	public void testGetBuckets() {
		LocalDateTime start = LocalDateTime.now().minusDays(3);
		LocalDateTime end = LocalDateTime.now();
		DayIntervals dayIntervals = new DayIntervals(start, end);
		List<LocalDateTime> buckets = dayIntervals.getBuckets();
		Assertions.assertEquals(4, buckets.size());
		Assertions.assertTrue(buckets.get(0).isBefore(buckets.get(1)));
		Assertions.assertTrue(buckets.get(1).isBefore(buckets.get(2)));
		Assertions.assertTrue(buckets.get(2).isBefore(buckets.get(3)));
		Assertions.assertEquals(0, buckets.get(0).compareTo(start.toLocalDate().atStartOfDay()));
		Assertions.assertEquals(0, buckets.get(3).compareTo(end.toLocalDate().atStartOfDay()));
	}

}
