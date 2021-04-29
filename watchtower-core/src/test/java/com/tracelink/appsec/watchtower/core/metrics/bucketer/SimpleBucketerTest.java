package com.tracelink.appsec.watchtower.core.metrics.bucketer;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.Collections;
import java.util.List;
import java.util.function.Function;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class SimpleBucketerTest {

	@Test
	public void testGetLabelsDays() {
		SimpleBucketer<LocalDateTime> bucketer = new SimpleBucketer<>(BucketerTimePeriod.LAST_WEEK,
				LocalDateTime::now, Function.identity());
		BucketIntervals intervals = bucketer.getBucketIntervals();
		Assertions.assertTrue(intervals instanceof DayIntervals);
	}

	@Test
	public void testGetLabelsWeeks() {
		SimpleBucketer<LocalDateTime> bucketer = new SimpleBucketer<>(
				BucketerTimePeriod.LAST_FOUR_WEEKS,
				LocalDateTime::now, Function.identity());
		BucketIntervals intervals = bucketer.getBucketIntervals();
		Assertions.assertTrue(intervals instanceof WeekIntervals);
	}

	@Test
	public void testGetLabelsMonths() {
		SimpleBucketer<LocalDateTime> bucketer = new SimpleBucketer<>(
				BucketerTimePeriod.LAST_SIX_MONTHS,
				LocalDateTime::now, Function.identity());
		BucketIntervals intervals = bucketer.getBucketIntervals();
		Assertions.assertTrue(intervals instanceof MonthIntervals);
	}

	@Test
	public void testGetLabelsAllTime() {
		SimpleBucketer<LocalDateTime> bucketer = new SimpleBucketer<>(BucketerTimePeriod.ALL_TIME,
				() -> LocalDateTime.now().minusMonths(2), Function.identity());
		BucketIntervals intervals = bucketer.getBucketIntervals();
		Assertions.assertTrue(intervals instanceof MonthIntervals);
	}

	@Test
	public void testSimpleBucketerInvalidPeriod() {
		Assertions.assertThrows(IllegalArgumentException.class,
				() -> {
					new SimpleBucketer<>(BucketerTimePeriod.ofPeriod("foo"), LocalDateTime::now,
							Function.identity());
				});
	}

	@Test
	public void testPutItemsInBuckets() {
		SimpleBucketer<LocalDateTime> bucketer = new SimpleBucketer<>(BucketerTimePeriod.LAST_WEEK,
				LocalDateTime::now, Function.identity());
		List<List<LocalDateTime>> bucketedItems = bucketer
				.putItemsInBuckets(Collections.singletonList(LocalDateTime.now().minusDays(3)));
		Assertions.assertEquals(7, bucketedItems.size());
		Assertions.assertFalse(bucketedItems.get(3).isEmpty());
		Assertions.assertEquals(bucketedItems.get(3).get(0).toLocalDate(),
				LocalDate.now().minusDays(3));

	}

}
