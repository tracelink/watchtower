package com.tracelink.appsec.watchtower.core.alerting;

import java.util.List;
import java.util.Optional;

import org.hamcrest.MatcherAssert;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.mockito.ArgumentCaptor;
import org.mockito.BDDMockito;

import com.tracelink.appsec.watchtower.core.alerting.entity.AlertChannelEntity;
import com.tracelink.appsec.watchtower.core.alerting.entity.AlertRouteEntity;
import com.tracelink.appsec.watchtower.core.alerting.repository.AlertChannelRepository;
import com.tracelink.appsec.watchtower.core.alerting.repository.AlertLogRepository;
import com.tracelink.appsec.watchtower.core.alerting.repository.AlertRouteRepository;
import com.tracelink.appsec.watchtower.core.encryption.model.EncryptionType;
import com.tracelink.appsec.watchtower.core.logging.CoreLogWatchExtension;
import com.tracelink.appsec.watchtower.core.rule.RulePriority;

public class AlertSettingsServiceTest {

	@RegisterExtension
	public CoreLogWatchExtension logWatcher =
			CoreLogWatchExtension.forClass(AlertSettingsService.class);

	private AlertChannelRepository channelRepository;

	private AlertRouteRepository routeRepository;

	private GoogleChatSender sender;

	private AlertSettingsService service;

	private AlertSettingsService service(EncryptionType encryption, boolean production) {
		return new AlertSettingsService(channelRepository, routeRepository,
				BDDMockito.mock(AlertLogRepository.class), new AlertTypeRegistry(), sender,
				encryption, production);
	}

	@BeforeEach
	public void setup() {
		channelRepository = BDDMockito.mock(AlertChannelRepository.class);
		routeRepository = BDDMockito.mock(AlertRouteRepository.class);
		sender = BDDMockito.mock(GoogleChatSender.class);
		BDDMockito.when(channelRepository.save(BDDMockito.any()))
				.thenAnswer(invocation -> invocation.getArgument(0));
		service = service(EncryptionType.ENVIRONMENT, true);
	}

	private AlertChannelEntity savedChannel() {
		ArgumentCaptor<AlertChannelEntity> captor =
				ArgumentCaptor.forClass(AlertChannelEntity.class);
		BDDMockito.verify(channelRepository, BDDMockito.atLeastOnce()).save(captor.capture());
		return captor.getValue();
	}

	@Test
	public void testAddsAChannelAndNeverLogsItsUrl() {
		service.addChannel(" appsec-alerts ", GoogleChatWebhookTest.VALID, "alice");

		AlertChannelEntity saved = savedChannel();
		Assertions.assertEquals("appsec-alerts", saved.getName());
		Assertions.assertEquals(GoogleChatWebhookTest.VALID, saved.getWebhookUrl());
		Assertions.assertEquals("alice", saved.getCreatedBy());
		String logs = String.join("\n", logWatcher.getFormattedMessages());
		MatcherAssert.assertThat(logs, Matchers.containsString("alice"));
		MatcherAssert.assertThat(logs, Matchers.not(Matchers.containsString("SyExample")));
	}

	@Test
	public void testRefusesAChannelThatIsNotGoogleChat() {
		Assertions.assertThrows(IllegalArgumentException.class,
				() -> service.addChannel("x", "https://evil.example/hook", "alice"));
		BDDMockito.verify(channelRepository, BDDMockito.never()).save(BDDMockito.any());
	}

	@Test
	public void testRefusesToStoreAWebhookInPlaintextInProduction() {
		service = service(EncryptionType.NONE, true);

		IllegalArgumentException e = Assertions.assertThrows(IllegalArgumentException.class,
				() -> service.addChannel("appsec", GoogleChatWebhookTest.VALID, "alice"));

		MatcherAssert.assertThat(e.getMessage(), Matchers.containsString("encryption"));
	}

	@Test
	public void testAllowsUnencryptedWebhooksOutsideProduction() {
		service = service(EncryptionType.NONE, false);

		service.addChannel("appsec", GoogleChatWebhookTest.VALID, "alice");

		BDDMockito.verify(channelRepository).save(BDDMockito.any());
	}

	@Test
	public void testRefusesADuplicateChannelName() {
		BDDMockito.when(channelRepository.findByName("appsec"))
				.thenReturn(new AlertChannelEntity());

		Assertions.assertThrows(IllegalArgumentException.class,
				() -> service.addChannel("appsec", GoogleChatWebhookTest.VALID, "alice"));
	}

	@Test
	public void testUpdateWithABlankUrlKeepsTheStoredOne() {
		AlertChannelEntity existing = new AlertChannelEntity();
		existing.setName("appsec");
		existing.setWebhookUrl(GoogleChatWebhookTest.VALID);
		BDDMockito.when(channelRepository.findById(4L)).thenReturn(Optional.of(existing));

		service.updateChannel(4L, "appsec", " ", false, "bob");

		Assertions.assertEquals(GoogleChatWebhookTest.VALID, existing.getWebhookUrl());
		Assertions.assertFalse(existing.isEnabled());
		Assertions.assertEquals("bob", existing.getUpdatedBy());
	}

	@Test
	public void testChannelViewsAreMasked() {
		AlertChannelEntity existing = new AlertChannelEntity();
		existing.setName("appsec");
		existing.setWebhookUrl(GoogleChatWebhookTest.VALID);
		BDDMockito.when(channelRepository.findAll()).thenReturn(List.of(existing));

		AlertSettingsService.ChannelView view = service.getChannels().get(0);

		Assertions.assertEquals(GoogleChatWebhook.mask(GoogleChatWebhookTest.VALID),
				view.maskedUrl());
		MatcherAssert.assertThat(view.toString(), Matchers.not(Matchers.containsString("SyExample")));
	}

	@Test
	public void testAChannelWithRoutesCannotBeDeleted() {
		BDDMockito.when(channelRepository.findById(4L))
				.thenReturn(Optional.of(new AlertChannelEntity()));
		BDDMockito.when(routeRepository.existsByChannel_Id(4L)).thenReturn(true);

		Assertions.assertThrows(IllegalArgumentException.class,
				() -> service.deleteChannel(4L, "bob"));
	}

	@Test
	public void testTestAlertRecordsTheOutcome() {
		AlertChannelEntity existing = new AlertChannelEntity();
		existing.setWebhookUrl(GoogleChatWebhookTest.VALID);
		BDDMockito.when(channelRepository.findById(4L)).thenReturn(Optional.of(existing));
		BDDMockito.when(sender.send(BDDMockito.eq(GoogleChatWebhookTest.VALID), BDDMockito.any(),
				BDDMockito.isNull())).thenReturn(GoogleChatSender.SendResult.failed("HTTP 404"));

		String outcome = service.testChannel(4L, "bob");

		Assertions.assertEquals("Failed: HTTP 404", outcome);
		Assertions.assertEquals("Failed: HTTP 404", existing.getLastTestStatus());
		Assertions.assertNotNull(existing.getLastTestAt());
	}

	@Test
	public void testAddsAValidRoute() {
		AlertChannelEntity channel = new AlertChannelEntity();
		BDDMockito.when(channelRepository.findById(4L)).thenReturn(Optional.of(channel));

		service.addRoute(new AlertSettingsService.RouteRequest(
				AlertTypeRegistry.SCANNER_FAILURE, 4L, RulePriority.HIGH, "bitbucket",
				"payments-*", "payments-sandbox", AlertAggregation.PER_FINDING, 24), "alice");

		ArgumentCaptor<AlertRouteEntity> route = ArgumentCaptor.forClass(AlertRouteEntity.class);
		BDDMockito.verify(routeRepository).save(route.capture());
		Assertions.assertSame(channel, route.getValue().getChannel());
		Assertions.assertEquals("payments-*", route.getValue().getRepoInclude());
		Assertions.assertEquals(24, route.getValue().getDedupeWindowHours());
		Assertions.assertEquals("alice", route.getValue().getUpdatedBy());
	}

	@Test
	public void testRejectsInvalidRoutes() {
		BDDMockito.when(channelRepository.findById(4L))
				.thenReturn(Optional.of(new AlertChannelEntity()));
		List<AlertSettingsService.RouteRequest> invalid = List.of(
				new AlertSettingsService.RouteRequest("NO_SUCH_TYPE", 4L, null, null, null, null,
						AlertAggregation.PER_SCAN, 24),
				new AlertSettingsService.RouteRequest(AlertTypeRegistry.SCANNER_FAILURE, 9L, null,
						null, null, null, AlertAggregation.PER_SCAN, 24),
				new AlertSettingsService.RouteRequest(AlertTypeRegistry.SCANNER_FAILURE, 4L, null,
						null, "bad'glob", null, AlertAggregation.PER_SCAN, 24),
				new AlertSettingsService.RouteRequest(AlertTypeRegistry.SCANNER_FAILURE, 4L, null,
						null, null, null, AlertAggregation.PER_SCAN, 0),
				new AlertSettingsService.RouteRequest(AlertTypeRegistry.SCANNER_FAILURE, 4L, null,
						null, null, null, null, 24));

		for (AlertSettingsService.RouteRequest request : invalid) {
			Assertions.assertThrows(IllegalArgumentException.class,
					() -> service.addRoute(request, "alice"), request.toString());
			Assertions.assertThrows(IllegalArgumentException.class,
					() -> service.updateRoute(1L, request, "alice"), request.toString());
		}
		BDDMockito.verify(routeRepository, BDDMockito.never()).save(BDDMockito.any());
	}

	@Test
	public void testUpdateRouteChangesEveryFieldButKeepsItsEnabledState() {
		AlertChannelEntity oldChannel = new AlertChannelEntity();
		AlertChannelEntity newChannel = new AlertChannelEntity();
		BDDMockito.when(channelRepository.findById(4L)).thenReturn(Optional.of(newChannel));
		AlertRouteEntity existing = new AlertRouteEntity();
		existing.setAlertType(AlertTypeRegistry.SCANNER_FAILURE);
		existing.setChannel(oldChannel);
		existing.setMinPriority(RulePriority.HIGH);
		existing.setRepoInclude("old-*");
		existing.setAggregation(AlertAggregation.PER_SCAN);
		existing.setDedupeWindowHours(720);
		existing.setEnabled(false);
		BDDMockito.when(routeRepository.findById(1L)).thenReturn(Optional.of(existing));

		service.updateRoute(1L, new AlertSettingsService.RouteRequest(
				AlertTypeRegistry.SCM_REVIEW_ACTION_FAILED, 4L, null, null, null, "sandbox-*",
				AlertAggregation.PER_FINDING, 24), "bob");

		ArgumentCaptor<AlertRouteEntity> route = ArgumentCaptor.forClass(AlertRouteEntity.class);
		BDDMockito.verify(routeRepository).save(route.capture());
		AlertRouteEntity saved = route.getValue();
		Assertions.assertSame(existing, saved);
		Assertions.assertEquals(AlertTypeRegistry.SCM_REVIEW_ACTION_FAILED, saved.getAlertType());
		Assertions.assertSame(newChannel, saved.getChannel());
		Assertions.assertNull(saved.getMinPriority());
		Assertions.assertNull(saved.getRepoInclude());
		Assertions.assertEquals("sandbox-*", saved.getRepoExclude());
		Assertions.assertEquals(AlertAggregation.PER_FINDING, saved.getAggregation());
		Assertions.assertEquals(24, saved.getDedupeWindowHours());
		Assertions.assertFalse(saved.isEnabled());
		Assertions.assertEquals("bob", saved.getUpdatedBy());
	}

	@Test
	public void testUpdatingAnUnknownRouteFails() {
		BDDMockito.when(channelRepository.findById(4L))
				.thenReturn(Optional.of(new AlertChannelEntity()));

		Assertions.assertThrows(IllegalArgumentException.class,
				() -> service.updateRoute(99L, new AlertSettingsService.RouteRequest(
						AlertTypeRegistry.SCANNER_FAILURE, 4L, null, null, null, null,
						AlertAggregation.PER_SCAN, 24), "bob"));
	}

	@Test
	public void testHistoryRejectsUnknownFiltersAndOversizedPages() {
		var history = service(EncryptionType.NONE, false);
		Assertions.assertThrows(IllegalArgumentException.class,
				() -> history.history("DELIVERED", "all", 0, 25, java.util.Map.of()));
		Assertions.assertThrows(IllegalArgumentException.class,
				() -> history.history("all", "NO_SUCH_TYPE", 0, 25, java.util.Map.of()));
		Assertions.assertThrows(IllegalArgumentException.class,
				() -> history.history("all", "all", 0, 101, java.util.Map.of()));
		Assertions.assertFalse(history.isCredentialEncryptionActive());
		Assertions.assertTrue(service(EncryptionType.ENVIRONMENT, false).isCredentialEncryptionActive());
	}
}
