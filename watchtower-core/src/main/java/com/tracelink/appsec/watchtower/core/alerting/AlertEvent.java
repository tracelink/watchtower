package com.tracelink.appsec.watchtower.core.alerting;

import java.util.List;

/**
 * Something worth alerting on, raised through {@link AlertService#raise(AlertEvent)}. Routes
 * decide where it goes; a route aggregating per scan sends one message with every new item, a
 * route aggregating per finding sends one message per item.
 *
 * @param type      the {@link AlertType#key()}
 * @param apiLabel  the SCM integration, for route filters; may be null
 * @param repoName  the repository, for route filters; may be null
 * @param title     the message heading
 * @param link      a Watchtower link for details; may be null
 * @param threadKey groups related messages into one thread (e.g. per pull request); may be null
 * @param items     what is being reported
 * @author Watchtower
 */
public record AlertEvent(String type, String apiLabel, String repoName, String title,
		String link, String threadKey, List<AlertItem> items) {

	public AlertEvent {
		items = List.copyOf(items);
	}
}
