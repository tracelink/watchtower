package com.tracelink.appsec.watchtower.core.alerting.repository;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.transaction.annotation.Transactional;

import com.tracelink.appsec.watchtower.core.WatchtowerTestApplication;
import com.tracelink.appsec.watchtower.core.alerting.AlertAggregation;
import com.tracelink.appsec.watchtower.core.alerting.entity.AlertChannelEntity;
import com.tracelink.appsec.watchtower.core.alerting.entity.AlertRouteEntity;
import com.tracelink.appsec.watchtower.core.rule.RulePriority;

import jakarta.persistence.EntityManager;

/**
 * Persists routes through the real Flyway schema (V049) so entity/column mismatches fail here
 * instead of on the deployed database.
 */
@ExtendWith(SpringExtension.class)
@SpringBootTest(classes = WatchtowerTestApplication.class)
@Transactional
public class AlertRouteRepositoryTest {

	@Autowired
	private AlertChannelRepository channelRepository;

	@Autowired
	private AlertRouteRepository routeRepository;

	@Autowired
	private EntityManager entityManager;

	@Test
	public void testSaveRouteWithoutMinimumPriority() {
		long id = saveRoute(null);

		Assertions.assertNull(reload(id).getMinPriority());
	}

	@Test
	public void testSaveRouteWithMinimumPriority() {
		long id = saveRoute(RulePriority.MEDIUM_HIGH);

		Assertions.assertEquals(RulePriority.MEDIUM_HIGH, reload(id).getMinPriority());
	}

	@Test
	public void testMinimumPriorityStoredAsNumberInTinyintColumn() {
		long id = saveRoute(RulePriority.HIGH);
		entityManager.flush();

		Object stored = entityManager
				.createNativeQuery("SELECT min_priority FROM alert_routes WHERE route_id = :id")
				.setParameter("id", id).getSingleResult();

		Assertions.assertEquals(RulePriority.HIGH.getPriority(),
				((Number) stored).intValue());
	}

	private long saveRoute(RulePriority minPriority) {
		AlertChannelEntity channel = new AlertChannelEntity();
		channel.setName("test-channel-" + System.nanoTime());
		channel.setType(AlertChannelEntity.GOOGLE_CHAT);
		channel.setWebhookUrl("https://chat.googleapis.com/v1/spaces/TEST/messages?key=test");
		channel.setEnabled(true);
		channel.setCreatedBy("tester");
		channel.setUpdatedBy("tester");
		channel.setUpdatedAt(System.currentTimeMillis());
		channelRepository.save(channel);

		AlertRouteEntity route = new AlertRouteEntity();
		route.setAlertType("SCANNER_FAILURE");
		route.setChannel(channel);
		route.setMinPriority(minPriority);
		route.setAggregation(AlertAggregation.PER_SCAN);
		route.setDedupeWindowHours(720);
		route.setUpdatedBy("tester");
		route.setUpdatedAt(System.currentTimeMillis());
		return routeRepository.saveAndFlush(route).getId();
	}

	private AlertRouteEntity reload(long id) {
		entityManager.flush();
		entityManager.clear();
		return routeRepository.findById(id).orElseThrow();
	}
}
