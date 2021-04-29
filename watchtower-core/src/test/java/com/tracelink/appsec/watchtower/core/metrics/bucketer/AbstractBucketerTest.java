package com.tracelink.appsec.watchtower.core.metrics.bucketer;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.Collections;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

public class AbstractBucketerTest {

	@Test
	public void testInvalidBuckets() {
		AbstractBucketer<LocalDate> bucketer = new AbstractBucketer<LocalDate>() {
			@Override
			public BucketIntervals getBucketIntervals() {
				DayIntervals dayIntervals = new DayIntervals(LocalDateTime.now().minusDays(5),
						LocalDateTime.now());
				ReflectionTestUtils.setField(dayIntervals, "start", LocalDateTime.now().plusDays(1),
						LocalDateTime.class);
				return dayIntervals;
			}

			@Override
			public boolean itemBelongsInBucket(LocalDate item, LocalDateTime bucketStart,
					LocalDateTime bucketEnd) {
				return false;
			}
		};
		Assertions.assertTrue(
				bucketer.putItemsInBuckets(Collections.singletonList(LocalDate.now())).isEmpty());
	}

}
