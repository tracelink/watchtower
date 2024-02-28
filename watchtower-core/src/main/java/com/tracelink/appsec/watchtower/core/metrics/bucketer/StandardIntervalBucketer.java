package com.tracelink.appsec.watchtower.core.metrics.bucketer;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.function.Supplier;

/**
 * Abstract implementation of the {@link AbstractBucketer} that implements
 * {@link AbstractBucketer#getBucketIntervals()} and constructs a {@link BucketIntervals} from a set
 * of standard options.
 * <p>
 * This class does not implement
 * {@link AbstractBucketer#itemBelongsInBucket(Object, LocalDateTime, LocalDateTime)}, which is left
 * for concrete classes to implement.
 *
 * @author mcool
 * @param <T> type of the items to be put into buckets
 */
public abstract class StandardIntervalBucketer<T> extends AbstractBucketer<T> {

	private final BucketIntervals bucketIntervals;

	/**
	 * Constructs an instance of this bucketer using the given {@link BucketerTimePeriod}
	 * representing a period of time. Also instantiates a {@link BucketIntervals} to represent days
	 * for the past week, weeks for the past four weeks, months for the past six months, or months
	 * since the earliest {@link LocalDateTime}, which is supplied by the given {@link Supplier}.
	 * The supplier will only be executed if the given period is
	 * {@link BucketerTimePeriod#ALL_TIME}.
	 *
	 * @param timePeriod               the time period for the {@link BucketIntervals}
	 * @param earliestDateTimeSupplier supplier function to return the earliest date for the
	 *                                 {@link BucketIntervals} in the case of 'all-time'
	 * @throws IllegalArgumentException if the given time period does not match one of the standard
	 *                                  options
	 */
	public StandardIntervalBucketer(BucketerTimePeriod timePeriod,
			Supplier<LocalDateTime> earliestDateTimeSupplier) throws IllegalArgumentException {
		switch (timePeriod) {
			case LAST_WEEK:
				bucketIntervals = new DayIntervals(
						LocalDate.now().minusDays(6).atStartOfDay(),
						LocalDate.now().plusDays(1).atStartOfDay());
				break;
			case LAST_FOUR_WEEKS:
				bucketIntervals = new WeekIntervals(LocalDate.now().minusDays(27).atStartOfDay(),
						LocalDate.now().plusDays(1).atStartOfDay());
				break;
			case LAST_SIX_MONTHS:
				bucketIntervals = new MonthIntervals(
						LocalDate.now().withDayOfMonth(1).minusMonths(5).atStartOfDay(),
						LocalDate.now().plusDays(1).atStartOfDay());
				break;
			case LAST_YEAR:
				bucketIntervals = new MonthIntervals(
						LocalDate.now().withMonth(1).withDayOfMonth(1).minusYears(1).atStartOfDay(),
						LocalDate.now().withMonth(1).withDayOfMonth(1).atStartOfDay());
				break;
			case ALL_TIME:
				bucketIntervals = new MonthIntervals(
						earliestDateTimeSupplier.get().withDayOfMonth(1),
						LocalDate.now().plusDays(1).atStartOfDay());
				break;
			default:
				throw new IllegalArgumentException("Unknown time period");
		}
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public BucketIntervals getBucketIntervals() {
		return bucketIntervals;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public abstract boolean itemBelongsInBucket(T item, LocalDateTime bucketStart,
			LocalDateTime bucketEnd);
}
