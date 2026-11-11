package com.tracelink.appsec.watchtower.core.scan.code.scm.pr.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.Collections;
import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.BDDMockito;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.entity.PullRequestSyncSettingsEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.repository.PullRequestSyncSettingsRepository;

@ExtendWith(SpringExtension.class)
public class PullRequestSyncSettingsServiceTest {

	@MockitoBean
	private PullRequestSyncSettingsRepository mockSettingsRepository;

	private PullRequestSyncSettingsService settingsService;

	@BeforeEach
	public void setup() {
		settingsService = new PullRequestSyncSettingsService(mockSettingsRepository);
	}

	@Test
	public void testGetSettingsCreatesDefaultWhenEmpty() {
		BDDMockito.when(mockSettingsRepository.findAll()).thenReturn(Collections.emptyList());
		PullRequestSyncSettingsEntity defaultEntity = new PullRequestSyncSettingsEntity();
		BDDMockito.when(mockSettingsRepository.saveAndFlush(BDDMockito.any()))
				.thenReturn(defaultEntity);

		PullRequestSyncSettingsEntity result = settingsService.getSettings();

		assertEquals(24, result.getSyncFrequencyHours());
		BDDMockito.verify(mockSettingsRepository).saveAndFlush(BDDMockito.any());
	}

	@Test
	public void testGetSettingsReturnsExistingRow() {
		PullRequestSyncSettingsEntity existing = new PullRequestSyncSettingsEntity();
		existing.setSyncFrequencyHours(12);
		BDDMockito.when(mockSettingsRepository.findAll())
				.thenReturn(List.of(existing));

		PullRequestSyncSettingsEntity result = settingsService.getSettings();

		assertEquals(12, result.getSyncFrequencyHours());
		BDDMockito.verify(mockSettingsRepository, BDDMockito.never())
				.saveAndFlush(BDDMockito.any());
	}

	@Test
	public void testUpdateSyncFrequencyHoursPersistsValidValue() {
		PullRequestSyncSettingsEntity existing = new PullRequestSyncSettingsEntity();
		BDDMockito.when(mockSettingsRepository.findAll())
				.thenReturn(List.of(existing));

		settingsService.updateSyncFrequencyHours(48);

		assertEquals(48, existing.getSyncFrequencyHours());
		BDDMockito.verify(mockSettingsRepository).saveAndFlush(existing);
	}

	@Test
	public void testUpdateSyncFrequencyHoursRejectsZero() {
		assertThrows(IllegalArgumentException.class,
				() -> settingsService.updateSyncFrequencyHours(0));
		BDDMockito.verify(mockSettingsRepository, BDDMockito.never())
				.saveAndFlush(BDDMockito.any());
	}

	@Test
	public void testUpdateSyncFrequencyHoursRejectsNegative() {
		assertThrows(IllegalArgumentException.class,
				() -> settingsService.updateSyncFrequencyHours(-5));
	}

	@Test
	public void testUpdateFullSourceFileThresholdPersistsValidValue() {
		PullRequestSyncSettingsEntity existing = new PullRequestSyncSettingsEntity();
		BDDMockito.when(mockSettingsRepository.findAll())
				.thenReturn(List.of(existing));

		settingsService.updateFullSourceFileThreshold(10);

		assertEquals(10, existing.getFullSourceFileThreshold());
		BDDMockito.verify(mockSettingsRepository).saveAndFlush(existing);
	}

	@Test
	public void testUpdateFullSourceFileThresholdRejectsZero() {
		assertThrows(IllegalArgumentException.class,
				() -> settingsService.updateFullSourceFileThreshold(0));
		BDDMockito.verify(mockSettingsRepository, BDDMockito.never())
				.saveAndFlush(BDDMockito.any());
	}

	@Test
	public void testUpdateFullSourceFileThresholdRejectsNegative() {
		assertThrows(IllegalArgumentException.class,
				() -> settingsService.updateFullSourceFileThreshold(-5));
	}

	@Test
	public void testUpdatePerformanceWindowDaysPersistsValidValue() {
		PullRequestSyncSettingsEntity existing = new PullRequestSyncSettingsEntity();
		BDDMockito.when(mockSettingsRepository.findAll()).thenReturn(List.of(existing));

		settingsService.updatePerformanceWindowDays(30);

		assertEquals(30, existing.getPerformanceWindowDays());
		BDDMockito.verify(mockSettingsRepository).saveAndFlush(existing);
	}

	@Test
	public void testUpdatePerformanceWindowDaysRejectsOutsideSupportedRange() {
		assertThrows(IllegalArgumentException.class,
				() -> settingsService.updatePerformanceWindowDays(0));
		assertThrows(IllegalArgumentException.class,
				() -> settingsService.updatePerformanceWindowDays(366));
	}

	@Test
	public void testUpdateSettingsValidatesThenPersistsAllValuesOnce() {
		PullRequestSyncSettingsEntity existing = new PullRequestSyncSettingsEntity();
		BDDMockito.when(mockSettingsRepository.findAll()).thenReturn(List.of(existing));

		settingsService.updateSettings(48, 25, 30);

		assertEquals(48, existing.getSyncFrequencyHours());
		assertEquals(25, existing.getFullSourceFileThreshold());
		assertEquals(30, existing.getPerformanceWindowDays());
		BDDMockito.verify(mockSettingsRepository).saveAndFlush(existing);
	}

	@Test
	public void testUpdateSettingsDoesNotPartiallyMutateWhenAnyValueIsInvalid() {
		PullRequestSyncSettingsEntity existing = new PullRequestSyncSettingsEntity();
		BDDMockito.when(mockSettingsRepository.findAll()).thenReturn(List.of(existing));

		assertThrows(IllegalArgumentException.class,
				() -> settingsService.updateSettings(48, 25, 366));

		assertEquals(24, existing.getSyncFrequencyHours());
		BDDMockito.verify(mockSettingsRepository, BDDMockito.never())
				.saveAndFlush(BDDMockito.any());
	}

	@Test
	public void testRecordSyncCompletedSetsTimestamp() {
		PullRequestSyncSettingsEntity existing = new PullRequestSyncSettingsEntity();
		BDDMockito.when(mockSettingsRepository.findAll())
				.thenReturn(List.of(existing));

		settingsService.recordSyncCompleted(12345L);

		assertEquals(12345L, existing.getLastSyncCompletedAt());
		BDDMockito.verify(mockSettingsRepository).saveAndFlush(existing);
	}

	@Test
	public void testUpdateSyncFrequencyMinutes() {
		PullRequestSyncSettingsEntity existing = new PullRequestSyncSettingsEntity();
		BDDMockito.when(mockSettingsRepository.findAll()).thenReturn(List.of(existing));

		settingsService.updateSyncFrequencyMinutes(10);

		assertEquals(10, existing.getSyncFrequencyMinutes());
		assertEquals(1, existing.getSyncFrequencyHours(), "the older hours column stays sensible");
		BDDMockito.verify(mockSettingsRepository).saveAndFlush(existing);
	}

	@Test
	public void testASyncFrequencyBelowTheMinimumIsRefused() {
		IllegalArgumentException e = org.junit.jupiter.api.Assertions.assertThrows(IllegalArgumentException.class,
				() -> settingsService.updateSyncFrequencyMinutes(4));
		assertEquals("Please provide a sync frequency of at least 5 minutes", e.getMessage());
		org.junit.jupiter.api.Assertions.assertThrows(IllegalArgumentException.class,
				() -> settingsService.updateSettingsMinutes(1, 5, 7));
		BDDMockito.verify(mockSettingsRepository, BDDMockito.never()).saveAndFlush(BDDMockito.any());
	}

	@Test
	public void testARowSavedBeforeMinutesExistedKeepsItsConfiguredHours() {
		PullRequestSyncSettingsEntity legacy = new PullRequestSyncSettingsEntity();
		legacy.setSyncFrequencyHours(12);
		org.springframework.test.util.ReflectionTestUtils.setField(legacy, "syncFrequencyMinutes", null);
		assertEquals(720, legacy.getSyncFrequencyMinutes());
		assertEquals(15, new PullRequestSyncSettingsEntity().getSyncFrequencyMinutes(), "new installs sync every 15 minutes");
	}

	@Test
	public void testTheStatusCommentIsOnByDefaultAndCanBeSwitchedOff() {
		PullRequestSyncSettingsEntity existing = new PullRequestSyncSettingsEntity();
		BDDMockito.when(mockSettingsRepository.findAll()).thenReturn(List.of(existing));
		assertEquals(true, existing.isStatusCommentsEnabled());

		settingsService.updateStatusComments(false);

		assertEquals(false, existing.isStatusCommentsEnabled());
		BDDMockito.verify(mockSettingsRepository).saveAndFlush(existing);
	}

	@Test
	public void testAnUnchangedStatusCommentSwitchWritesNothing() {
		PullRequestSyncSettingsEntity existing = new PullRequestSyncSettingsEntity();
		BDDMockito.when(mockSettingsRepository.findAll()).thenReturn(List.of(existing));

		settingsService.updateStatusComments(true);

		BDDMockito.verify(mockSettingsRepository, BDDMockito.never()).saveAndFlush(BDDMockito.any());
	}
}
