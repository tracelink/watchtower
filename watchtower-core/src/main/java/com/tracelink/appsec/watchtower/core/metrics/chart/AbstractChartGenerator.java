package com.tracelink.appsec.watchtower.core.metrics.chart;

import com.tracelink.appsec.watchtower.core.metrics.bucketer.AbstractBucketer;
import java.util.LinkedList;
import java.util.List;
import net.minidev.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Generates chart data used to display metrics in the UI by combining metrics from multiple pages
 * of bucketed items of type {@code T} into an object of type {@code U}. The object of type {@code
 * U} represents summary information or statistics about the bucketed items. This class is designed
 * for use with the {@link AbstractBucketer} class to generate charts over a period of time by
 * "bucketing" interesting items into particular time windows. This class receives bucketed items,
 * extracts useful information from them, and then formats the results into data that can be
 * charted. It also supports the concept of paging, so that you do not need all bucketed items at
 * once and can avoid memory errors.
 *
 * @author mcool
 * @param <T> type of the bucketed items
 * @param <U> type of the summary information accumulated by this class
 */
public abstract class AbstractChartGenerator<T, U> {

	private static final Logger LOGGER = LoggerFactory.getLogger(AbstractChartGenerator.class);

	private final LinkedList<U> result = new LinkedList<>();

	/**
	 * Reduces the given list of lists of bucketed items to a list of objects of type {@code U},
	 * which are stored by this class in the {@code result} field. Each object of type {@code U} in
	 * the {@code result} field represents summary information about the items in one bucket of the
	 * given list. This method applies the {@link AbstractChartGenerator#accumulate(Object, List)}
	 * to each bucket of items and its corresponding partial result of type {@code U} that has been
	 * accumulated in the {@code result} field. If it is the first time this method has been called
	 * on an object of this class, the partial result on each call to {@link
	 * AbstractChartGenerator#accumulate(Object, List)} will be equivalent to the object returned
	 * by {@link AbstractChartGenerator#getIdentity()}. On subsequent calls, if the number of
	 * buckets in the given list does not match the length of the result, this method does nothing
	 * and logs an error.
	 *
	 * @param bucketedItems list of bucketed items, from which summary information will be gathered
	 *                      and stored by this chart generator
	 */
	public final void reduce(List<List<T>> bucketedItems) {
		if (result.isEmpty()) {
			bucketedItems.stream().map(items -> accumulate(getIdentity(), items))
					.forEach(result::add);
		} else if (result.size() == bucketedItems.size()) { // Avoid indexing errors
			bucketedItems.stream()
					.map(items -> accumulate(result.removeFirst(), items))
					.forEach(result::add);
		} else {
			LOGGER.warn("Number of buckets for partial results and bucketed items do not match");
		}
	}

	/**
	 * Gets the formatted data needed to render the chart generated by this class. Adds the given
	 * list of labels and any datasets from calling {@link AbstractChartGenerator#getDatasets(List)}
	 * with the {@code result} accumulated by this class.
	 *
	 * @param labels chart labels
	 * @return JSON object containing chart labels and datasets
	 */
	public final JSONObject getResults(List<String> labels) {
		JSONObject results = new JSONObject();
		results.put("labels", labels);
		getDatasets(result).forEach(results::put);
		return results;
	}

	/**
	 * Accumulates a result from a given partial result and a list of items. This method is intended
	 * to gather useful information from the list of items and summarize it in the returned object,
	 * along with any data already in the partial result.
	 *
	 * @param partialResult previous data to combine with information from the given list of items.
	 * @param items         new list of bucketed items from which to gather information
	 * @return object of type {@code U} that combines the information from the partial result and
	 * the bucketed items.
	 */
	protected abstract U accumulate(U partialResult, List<T> items);

	/**
	 * The identity object for the {@link AbstractChartGenerator#reduce(List)} method. This object
	 * serves as the base from which to accumulate the results of this chart.
	 *
	 * @return object of type {@code U} that forms the base for accumulation
	 */
	protected abstract U getIdentity();

	/**
	 * Transforms the given accumulated result into a {@link JSONObject} that contains datasets.
	 * Each of these datasets represents chart data. This method may also provide labels for the
	 * chart data that will override the default labels in {@link AbstractChartGenerator#getResults(List)}.
	 *
	 * @param result the accumulated result to format as chart data
	 * @return JSON object containing chart data (and potentially labels)
	 */
	protected abstract JSONObject getDatasets(List<U> result);

}
