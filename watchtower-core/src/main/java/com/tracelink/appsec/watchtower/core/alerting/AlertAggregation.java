package com.tracelink.appsec.watchtower.core.alerting;

/**
 * How a route turns an event's items into messages.
 *
 * @author Watchtower
 */
public enum AlertAggregation {
	/** One message listing every new item of the event. */
	PER_SCAN,
	/** One message per new item. */
	PER_FINDING
}
