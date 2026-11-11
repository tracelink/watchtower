package com.tracelink.appsec.watchtower.core.alerting;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;

import org.hamcrest.MatcherAssert;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.BDDMockito;

import com.tracelink.appsec.watchtower.core.alerting.entity.AlertChannelEntity;
import com.tracelink.appsec.watchtower.core.alerting.entity.AlertLogEntity;
import com.tracelink.appsec.watchtower.core.alerting.entity.AlertRouteEntity;
import com.tracelink.appsec.watchtower.core.alerting.repository.AlertDedupeRepository;
import com.tracelink.appsec.watchtower.core.alerting.repository.AlertLogRepository;
import com.tracelink.appsec.watchtower.core.alerting.repository.AlertRouteRepository;
import com.tracelink.appsec.watchtower.core.rule.RulePriority;

import io.micrometer.core.instrument.simple.SimpleMeterRegistry;

public class AlertServiceTest {

	private static final Instant NOW = Instant.parse("2026-09-25T12:00:00Z");

	private static final String TYPE = "SECRET_DETECTED";

	private AlertRouteRepository routeRepository;

	private AlertLogRepository logRepository;

	private AlertDedupeRepository dedupeRepository;

	private SimpleMeterRegistry meters;

	private AlertService service;

	@BeforeEach
	public void setup() {
		routeRepository = BDDMockito.mock(AlertRouteRepository.class);
		logRepository = BDDMockito.mock(AlertLogRepository.class);
		dedupeRepository = BDDMockito.mock(AlertDedupeRepository.class);
		meters = new SimpleMeterRegistry();
		AlertTypeRegistry registry = new AlertTypeRegistry();
		registry.register(TYPE, "A secret was found.", true);
		service = new AlertService(registry, routeRepository, logRepository, dedupeRepository,
				Clock.fixed(NOW, ZoneOffset.UTC), meters);
	}

	private static AlertRouteEntity route(AlertAggregation aggregation) {
		AlertChannelEntity channel = new AlertChannelEntity();
		channel.setName("appsec");
		AlertRouteEntity route = new AlertRouteEntity();
		route.setAlertType(TYPE);
		route.setChannel(channel);
		route.setAggregation(aggregation);
		return route;
	}

	private static AlertEvent event(AlertItem... items) {
		return new AlertEvent(TYPE, "bitbucket", "payments-service", "Secrets detected",
				"https://watchtower.example.invalid/scan/report/7", "pr-42", List.of(items));
	}

	private static AlertItem item(String key, RulePriority priority) {
		return new AlertItem(key, priority, key + " at " + priority);
	}

	private void givenRoutes(AlertRouteEntity... routes) {
		BDDMockito.when(routeRepository.findByAlertTypeAndEnabledTrue(TYPE))
				.thenReturn(List.of(routes));
	}

	private List<AlertLogEntity> queued() {
		ArgumentCaptor<AlertLogEntity> captor = ArgumentCaptor.forClass(AlertLogEntity.class);
		BDDMockito.verify(logRepository, BDDMockito.atLeast(0)).save(captor.capture());
		return captor.getAllValues();
	}

	@Test
	public void testPerScanRouteQueuesOneMessageWithEveryNewItem() {
		givenRoutes(route(AlertAggregation.PER_SCAN));

		service.raise(event(item("a", RulePriority.HIGH), item("b", RulePriority.MEDIUM)));

		List<AlertLogEntity> queued = queued();
		Assertions.assertEquals(1, queued.size());
		AlertLogEntity message = queued.get(0);
		Assertions.assertEquals(AlertStatus.PENDING, message.getStatus());
		Assertions.assertEquals(NOW.toEpochMilli(), message.getNextAttemptAt());
		Assertions.assertEquals("pr-42", message.getThreadKey());
		MatcherAssert.assertThat(message.getPayload(), Matchers.allOf(
				Matchers.containsString("*Secrets detected*"),
				Matchers.containsString("payments-service"),
				Matchers.containsString("a at HIGH"), Matchers.containsString("b at MEDIUM"),
				Matchers.containsString("<https://watchtower.example.invalid/scan/report/7|")));
	}

	@Test
	public void testPerFindingRouteQueuesAMessagePerItem() {
		givenRoutes(route(AlertAggregation.PER_FINDING));

		service.raise(event(item("a", RulePriority.HIGH), item("b", RulePriority.MEDIUM)));

		Assertions.assertEquals(2, queued().size());
	}

	@Test
	public void testAlreadyAlertedItemsAreNotRepeated() {
		AlertRouteEntity route = route(AlertAggregation.PER_SCAN);
		givenRoutes(route);
		BDDMockito.when(dedupeRepository.existsByRouteIdAndDedupeKeyAndCreatedAtGreaterThan(
				BDDMockito.eq(route.getId()), BDDMockito.eq(AlertService.dedupeKey(TYPE, "a")),
				BDDMockito.eq(NOW.minusSeconds(720L * 3600).toEpochMilli()))).thenReturn(true);

		service.raise(event(item("a", RulePriority.HIGH), item("b", RulePriority.HIGH)));

		AlertLogEntity message = queued().get(0);
		MatcherAssert.assertThat(message.getPayload(), Matchers.not(Matchers.containsString("a at")));
		MatcherAssert.assertThat(message.getPayload(), Matchers.containsString("b at HIGH"));
		BDDMockito.verify(dedupeRepository).saveAll(BDDMockito.argThat(saved ->
				((java.util.Collection<?>) saved).size() == 1));
	}

	@Test
	public void testNothingNewMeansNoMessage() {
		givenRoutes(route(AlertAggregation.PER_SCAN));
		BDDMockito.when(dedupeRepository.existsByRouteIdAndDedupeKeyAndCreatedAtGreaterThan(
				BDDMockito.anyLong(), BDDMockito.anyString(), BDDMockito.anyLong()))
				.thenReturn(true);

		service.raise(event(item("a", RulePriority.HIGH)));

		Assertions.assertEquals(List.of(), queued());
		Assertions.assertEquals(1.0, meters.get(AlertService.METRIC).tag("outcome", "deduped")
				.counter().count());
	}

	@Test
	public void testMinPriorityDropsLessSevereItems() {
		AlertRouteEntity route = route(AlertAggregation.PER_SCAN);
		route.setMinPriority(RulePriority.MEDIUM_HIGH);
		givenRoutes(route);

		service.raise(event(item("a", RulePriority.HIGH), item("b", RulePriority.MEDIUM)));

		MatcherAssert.assertThat(queued().get(0).getPayload(),
				Matchers.not(Matchers.containsString("b at")));
	}

	@Test
	public void testRepositoryAndLabelFiltersSelectRoutes() {
		AlertRouteEntity otherLabel = route(AlertAggregation.PER_SCAN);
		otherLabel.setApiLabelFilter("github");
		AlertRouteEntity excluded = route(AlertAggregation.PER_SCAN);
		excluded.setRepoExclude("payments-*");
		AlertRouteEntity notIncluded = route(AlertAggregation.PER_SCAN);
		notIncluded.setRepoInclude("billing-*, ledger");
		AlertRouteEntity included = route(AlertAggregation.PER_SCAN);
		included.setRepoInclude("billing-*, PAYMENTS-*");
		givenRoutes(otherLabel, excluded, notIncluded, included);

		service.raise(event(item("a", RulePriority.HIGH)));

		Assertions.assertEquals(1, queued().size());
	}

	@Test
	public void testDisabledChannelsAndUnknownTypesAreIgnored() {
		AlertRouteEntity route = route(AlertAggregation.PER_SCAN);
		route.getChannel().setEnabled(false);
		givenRoutes(route);

		service.raise(event(item("a", RulePriority.HIGH)));
		service.raise(new AlertEvent("NO_SUCH_TYPE", null, null, "t", null, null,
				List.of(item("a", null))));

		Assertions.assertEquals(List.of(), queued());
	}

	@Test
	public void testRaiseNeverThrows() {
		BDDMockito.when(routeRepository.findByAlertTypeAndEnabledTrue(TYPE))
				.thenThrow(new IllegalStateException("database down"));

		service.raise(event(item("a", RulePriority.HIGH)));

		Assertions.assertEquals(1.0, meters.get(AlertService.METRIC).tag("outcome", "failed")
				.counter().count());
	}

	@Test
	public void testLongEventsAreTruncatedButSayHowManyMore() {
		givenRoutes(route(AlertAggregation.PER_SCAN));
		AlertItem[] many = new AlertItem[AlertService.MAX_ITEMS_PER_MESSAGE + 5];
		for (int i = 0; i < many.length; i++) {
			many[i] = item("k" + i, RulePriority.HIGH);
		}

		service.raise(event(many));

		MatcherAssert.assertThat(queued().get(0).getPayload(), Matchers.containsString("5 more"));
	}
}
