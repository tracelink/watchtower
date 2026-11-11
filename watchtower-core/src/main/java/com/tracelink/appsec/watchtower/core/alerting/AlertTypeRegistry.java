package com.tracelink.appsec.watchtower.core.alerting;

import java.util.Collection;
import java.util.Comparator;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;

import org.springframework.stereotype.Service;

/**
 * The alert types routes can be configured for. Core registers its own; a module registers its
 * types while it is built.
 *
 * @author Watchtower
 */
@Service
public class AlertTypeRegistry {

	/** A scanner errored or timed out, so a scan's result is incomplete. */
	public static final String SCANNER_FAILURE = "SCANNER_FAILURE";

	/** Approving, requesting changes on, or commenting on a pull request failed. */
	public static final String SCM_REVIEW_ACTION_FAILED = "SCM_REVIEW_ACTION_FAILED";

	private static final Pattern KEY = Pattern.compile("[A-Z][A-Z0-9_]{2,63}");

	private final Map<String, AlertType> types = new ConcurrentHashMap<>();

	public AlertTypeRegistry() {
		register(SCANNER_FAILURE, "A scanner failed or timed out; the pull request result is"
				+ " incomplete.", false);
		register(SCM_REVIEW_ACTION_FAILED, "Watchtower could not approve, request changes on,"
				+ " or comment on a pull request.", false);
	}

	/**
	 * @param key                    upper-case identifier, e.g. {@code SECRET_DETECTED}
	 * @param description            what raises it
	 * @param supportsPriorityFilter whether its items carry a rule priority
	 * @throws IllegalArgumentException if the key is malformed or already registered differently
	 */
	public void register(String key, String description, boolean supportsPriorityFilter) {
		if (key == null || !KEY.matcher(key).matches()) {
			throw new IllegalArgumentException("Invalid alert type key: " + key);
		}
		AlertType type = new AlertType(key, description, supportsPriorityFilter);
		AlertType existing = types.putIfAbsent(key, type);
		if (existing != null && !existing.equals(type)) {
			throw new IllegalArgumentException("Alert type already registered: " + key);
		}
	}

	/**
	 * @param key an alert type key
	 * @return the type, if registered
	 */
	public Optional<AlertType> get(String key) {
		return Optional.ofNullable(key == null ? null : types.get(key));
	}

	/**
	 * @return every registered type, by key
	 */
	public Collection<AlertType> getTypes() {
		return types.values().stream().sorted(Comparator.comparing(AlertType::key)).toList();
	}
}
