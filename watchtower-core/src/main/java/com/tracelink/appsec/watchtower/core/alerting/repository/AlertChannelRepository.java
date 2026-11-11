package com.tracelink.appsec.watchtower.core.alerting.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.tracelink.appsec.watchtower.core.alerting.entity.AlertChannelEntity;

/**
 * Repository of alert channels.
 *
 * @author Watchtower
 */
public interface AlertChannelRepository extends JpaRepository<AlertChannelEntity, Long> {

	/**
	 * @param name a channel name
	 * @return the channel with that name, or null
	 */
	AlertChannelEntity findByName(String name);
}
