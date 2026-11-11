package com.tracelink.appsec.watchtower.core.alerting.repository;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;

import com.tracelink.appsec.watchtower.core.alerting.entity.AlertRouteEntity;

/**
 * Repository of alert routes.
 *
 * @author Watchtower
 */
public interface AlertRouteRepository extends JpaRepository<AlertRouteEntity, Long> {

	/**
	 * @param alertType an alert type key
	 * @return its enabled routes
	 */
	List<AlertRouteEntity> findByAlertTypeAndEnabledTrue(String alertType);

	/**
	 * @param channelId a channel
	 * @return true if any route sends to it
	 */
	boolean existsByChannel_Id(long channelId);
}
