package com.tracelink.appsec.watchtower.core.alerting;

/**
 * A kind of alert Watchtower can raise, registered by core or a module - like a privilege.
 *
 * @param key                    stable identifier routes refer to, e.g. {@code SECRET_DETECTED}
 * @param description            what raises it, shown in Alert Settings
 * @param supportsPriorityFilter whether its items carry a rule priority a route can filter on
 * @author Watchtower
 */
public record AlertType(String key, String description, boolean supportsPriorityFilter) {
}
