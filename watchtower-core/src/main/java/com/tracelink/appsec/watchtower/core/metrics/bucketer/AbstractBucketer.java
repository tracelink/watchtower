package com.tracelink.appsec.watchtower.core.metrics.bucketer;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.IntStream;

/**
 * Manages separating a list of items into zero or more buckets. A bucket is a period of time
 * represented by two {@link LocalDateTime} objects: a start time (inclusive) and an end time
 * (exclusive). The {@link LocalDateTime}s that form the bucket boundaries are provided by a {@link
 * BucketIntervals}. Items are added to buckets according to the {@link
 * AbstractBucketer#itemBelongsInBucket(Object, LocalDateTime, LocalDateTime)} method.
 *
 * @author mcool
 * @param <T> type of the items to be put into buckets
 */
public abstract class AbstractBucketer<T> {

	/**
	 * Puts items from the given list into buckets. Uses the {@link AbstractBucketer#getBucketIntervals()}
	 * method to get the bucket date boundaries. Uses the {@link AbstractBucketer#itemBelongsInBucket(Object,
	 * LocalDateTime, LocalDateTime)} method to determine if which items should be placed in the
	 * buckets. An item may be added to zero or more buckets. Returns a list of lists, where each
	 * inner list contains the contents of a single bucket.
	 *
	 * @param items list of items to be placed into buckets
	 * @return list of lists of items; if there are no buckets, will return an empty list
	 */
	public List<List<T>> putItemsInBuckets(List<T> items) {
		List<List<T>> bucketedItems = new ArrayList<>();
		List<LocalDateTime> bucketBoundaries = getBucketIntervals().getBuckets();
		// Prevent indexing errors
		if (bucketBoundaries.size() < 2) {
			return bucketedItems;
		}
		// Populate bucketed items with enough lists for each bucket
		IntStream.range(0, bucketBoundaries.size() - 1)
				.forEach(i -> bucketedItems.add(new ArrayList<>()));

		for (T item : items) {
			// Loop through buckets to find correct bucket for item
			for (int i = 0; i < bucketBoundaries.size() - 1; i++) {
				LocalDateTime startDate = bucketBoundaries.get(i);
				LocalDateTime endDate = bucketBoundaries.get(i + 1);

				// If the item belongs in this bucket, add item to the corresponding list
				if (itemBelongsInBucket(item, startDate, endDate)) {
					bucketedItems.get(i).add(item);
				}
			}
		}
		return bucketedItems;
	}

	/**
	 * Gets the {@link BucketIntervals} object that this bucketer uses to define its buckets and
	 * labels.
	 *
	 * @return the bucket intervals object used by this bucketer
	 */
	public abstract BucketIntervals getBucketIntervals();

	/**
	 * Determines whether the given item should be added to a bucket represented by the given start
	 * time and end time.
	 *
	 * @param item        the item to be added to a bucket
	 * @param bucketStart the start time (inclusive) of the bucket
	 * @param bucketEnd   the end time (exclusive) of the bucket
	 * @return true if the item should be added to the bucket; false otherwise
	 */
	public abstract boolean itemBelongsInBucket(T item, LocalDateTime bucketStart,
			LocalDateTime bucketEnd);

}
