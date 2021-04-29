package com.tracelink.appsec.watchtower.core.metrics.bucketer;

import java.time.LocalDateTime;
import java.util.function.Function;
import java.util.function.Supplier;

/**
 * Concrete implementation of the {@link StandardIntervalBucketer}. Uses the standard {@link
 * BucketIntervals} from the {@link StandardIntervalBucketer}. Implements {@link
 * AbstractBucketer#itemBelongsInBucket(Object, LocalDateTime, LocalDateTime)} using a simple
 * function from an item to a {@link LocalDateTime}.
 * @author mcool
 * @param <T> type of the items to be put into buckets
 */
public class SimpleBucketer<T> extends StandardIntervalBucketer<T> {

	private final Function<T, LocalDateTime> itemToLocalDateTimeFunction;

	/**
	 * Constructs an instance of this bucketer using the given {@link BucketerTimePeriod}
	 * representing a period of time and the given {@link Supplier} to invoke the super
	 * constructor. The given {@link Function} is used to convert an item into an associated {@link
	 * LocalDateTime}. The {@link AbstractBucketer#itemBelongsInBucket(Object, LocalDateTime,
	 * LocalDateTime)} method will return true if the {@link LocalDateTime} returned by applying
	 * this function to an item is between the given start and end times.
	 *
	 * @param timePeriod                  the time period for the {@link BucketIntervals}
	 * @param earliestDateTimeSupplier    supplier function to return the earliest date for the
	 *                                    {@link BucketIntervals} in the case of {@link
	 *                                    BucketerTimePeriod#ALL_TIME}
	 * @param itemToLocalDateTimeFunction function from an item to a {@link LocalDateTime}
	 * @throws IllegalArgumentException if the given time period does not match one of the standard
	 *                                  options
	 */
	public SimpleBucketer(BucketerTimePeriod timePeriod,
			Supplier<LocalDateTime> earliestDateTimeSupplier,
			Function<T, LocalDateTime> itemToLocalDateTimeFunction)
			throws IllegalArgumentException {
		super(timePeriod, earliestDateTimeSupplier);
		this.itemToLocalDateTimeFunction = itemToLocalDateTimeFunction;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public boolean itemBelongsInBucket(T item, LocalDateTime bucketStart, LocalDateTime bucketEnd) {
		LocalDateTime itemDate = itemToLocalDateTimeFunction.apply(item);
		return itemDate.compareTo(bucketStart) >= 0 && itemDate.compareTo(bucketEnd) < 0;
	}
}
