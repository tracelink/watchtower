package com.tracelink.appsec.watchtower.core.alerting.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.tracelink.appsec.watchtower.core.alerting.entity.AlertDedupeEntity;

/**
 * Repository of alerted-item records.
 *
 * @author Watchtower
 */
public interface AlertDedupeRepository extends JpaRepository<AlertDedupeEntity, Long> {

	/**
	 * @param routeId   a route
	 * @param dedupeKey an item's key
	 * @param since     start of the dedupe window
	 * @return true if the route alerted on the item within the window
	 */
	boolean existsByRouteIdAndDedupeKeyAndCreatedAtGreaterThan(long routeId, String dedupeKey,
			long since);
}
