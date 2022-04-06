package com.tracelink.appsec.watchtower.core.metrics;

import java.time.LocalDate;
import java.util.Arrays;
import java.util.Collections;
import java.util.Iterator;

import org.hamcrest.MatcherAssert;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.BDDMockito;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import com.tracelink.appsec.watchtower.core.scan.AbstractScanEntity;
import com.tracelink.appsec.watchtower.core.scan.code.CodeScanType;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.entity.PullRequestScanEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.entity.PullRequestViolationEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.service.PRScanResultService;
import com.tracelink.appsec.watchtower.core.scan.code.upload.entity.UploadScanEntity;
import com.tracelink.appsec.watchtower.core.scan.code.upload.entity.UploadViolationEntity;
import com.tracelink.appsec.watchtower.core.scan.code.upload.service.UploadScanResultService;

import net.minidev.json.JSONObject;

@ExtendWith(SpringExtension.class)
public class MetricsCacheServiceTest {

	@MockBean
	PRScanResultService mockPrScanResultService;
	@MockBean
	UploadScanResultService mockUploadScanResultService;

	MetricsCacheService metricsCacheService;

	private static String XXE_NAME = "XXE";
	private static String SER_NAME = "SERIALIZATION";

	@BeforeEach
	public void setup() {
		metricsCacheService =
				new MetricsCacheService(mockPrScanResultService, mockUploadScanResultService);
		configureDefaults();
	}

	private void configureDefaults() {
		PullRequestViolationEntity prXxe = BDDMockito.mock(PullRequestViolationEntity.class);
		BDDMockito.when(prXxe.getViolationName()).thenReturn(XXE_NAME);

		PullRequestViolationEntity prXxe2 = BDDMockito.mock(PullRequestViolationEntity.class);
		BDDMockito.when(prXxe2.getViolationName()).thenReturn(XXE_NAME);

		PullRequestViolationEntity prSer = BDDMockito.mock(PullRequestViolationEntity.class);
		BDDMockito.when(prSer.getViolationName()).thenReturn(SER_NAME);

		PullRequestScanEntity prScan1 = BDDMockito.mock(PullRequestScanEntity.class);
		BDDMockito.when(prScan1.getViolations()).thenReturn(Arrays.asList(prXxe, prSer));
		BDDMockito.when(prScan1.getEndDate()).thenReturn(LocalDate.now().atStartOfDay());
		BDDMockito.when(prScan1.getNumViolations()).thenReturn(2L);
		PullRequestScanEntity prScan2 = BDDMockito.mock(PullRequestScanEntity.class);
		BDDMockito.when(prScan2.getViolations()).thenReturn(Collections.singletonList(prXxe2));
		BDDMockito.when(prScan2.getEndDate())
				.thenReturn(LocalDate.now().minusDays(1).atStartOfDay());
		BDDMockito.when(prScan2.getNumViolations()).thenReturn(1L);
		BDDMockito.when(mockPrScanResultService
				.scanIteratorBetweenDates(BDDMockito.anyLong(), BDDMockito.anyLong()))
				.thenReturn(mockIterator(prScan1, prScan2));

		UploadViolationEntity uploadXxe = BDDMockito.mock(UploadViolationEntity.class);
		BDDMockito.when(uploadXxe.getViolationName()).thenReturn(XXE_NAME);

		UploadViolationEntity uploadXxe2 = BDDMockito.mock(UploadViolationEntity.class);
		BDDMockito.when(uploadXxe2.getViolationName()).thenReturn(XXE_NAME);

		UploadViolationEntity uploadSer = BDDMockito.mock(UploadViolationEntity.class);
		BDDMockito.when(uploadSer.getViolationName()).thenReturn(SER_NAME);

		UploadScanEntity uploadScan1 = BDDMockito.mock(UploadScanEntity.class);
		BDDMockito.when(uploadScan1.getViolations())
				.thenReturn(Arrays.asList(uploadXxe, uploadSer));
		BDDMockito.when(uploadScan1.getEndDate()).thenReturn(LocalDate.now().atStartOfDay());
		BDDMockito.when(uploadScan1.getNumViolations()).thenReturn(2L);
		UploadScanEntity uploadScan2 = BDDMockito.mock(UploadScanEntity.class);
		BDDMockito.when(uploadScan2.getViolations())
				.thenReturn(Collections.singletonList(uploadXxe2));
		BDDMockito.when(uploadScan2.getEndDate())
				.thenReturn(LocalDate.now().minusMonths(2).atStartOfDay());
		BDDMockito.when(uploadScan2.getNumViolations()).thenReturn(1L);
		BDDMockito.when(mockUploadScanResultService
				.scanIteratorBetweenDates(BDDMockito.anyLong(), BDDMockito.anyLong()))
				.thenReturn(mockIterator(uploadScan1, uploadScan2));

		BDDMockito.when(mockPrScanResultService.getOldestScanDate())
				.thenReturn(LocalDate.now().withDayOfMonth(1).minusMonths(1));
		BDDMockito.when(mockUploadScanResultService.getOldestScanDate())
				.thenReturn(LocalDate.now().withDayOfMonth(1).minusMonths(1));
	}

	Iterator<Page<AbstractScanEntity<?, ?>>> mockIterator(AbstractScanEntity<?, ?> scan1,
			AbstractScanEntity<?, ?> scan2) {
		return new Iterator<Page<AbstractScanEntity<?, ?>>>() {
			int count = 0;

			@Override
			public boolean hasNext() {
				boolean hasNext = count < 2;
				if (hasNext) {
					count++;
				} else {
					count = 0;
				}
				return hasNext;
			}

			@Override
			public Page<AbstractScanEntity<?, ?>> next() {
				if (count == 1) {
					return new PageImpl<>(Collections.singletonList(scan1));
				} else {
					return new PageImpl<>(Collections.singletonList(scan2));
				}
			}
		};
	}

	@Test
	public void testUpdateViolationsByType() {
		this.metricsCacheService.updateAllMetrics();
		JSONObject json =
				this.metricsCacheService.getViolationsByType(CodeScanType.PULL_REQUEST, "all-time");
		MatcherAssert.assertThat(json.getAsString("labels"),
				Matchers.allOf(Matchers.containsString(SER_NAME),
						Matchers.allOf(Matchers.containsString(XXE_NAME))));
		MatcherAssert.assertThat(json.getAsString("counts"),
				Matchers.allOf(Matchers.containsString("2"),
						Matchers.allOf(Matchers.containsString("1"))));

	}

	@Test
	public void testUpdateViolationsByPeriod() {
		this.metricsCacheService.updateAllMetrics();
		JSONObject json = this.metricsCacheService.getViolationsByPeriod(CodeScanType.UPLOAD,
				"last-six-months");
		MatcherAssert.assertThat(json.getAsString("counts"),
				Matchers.allOf(Matchers.containsString("2"),
						Matchers.allOf(Matchers.containsString("1"))));
	}

	@Test
	public void testUpdateViolationsByPeriodAndType() {
		this.metricsCacheService.updateAllMetrics();
		JSONObject json = this.metricsCacheService
				.getViolationsByPeriodAndType(CodeScanType.PULL_REQUEST, "last-four-weeks");
		MatcherAssert.assertThat(json.getAsString(XXE_NAME), Matchers.containsString("2"));
		MatcherAssert.assertThat(json.getAsString(SER_NAME), Matchers.containsString("1"));
	}

	@Test
	public void testUpdateScansByPeriod() {
		this.metricsCacheService.updateAllMetrics();
		JSONObject json =
				this.metricsCacheService.getScansByPeriod(CodeScanType.PULL_REQUEST, "last-week");
		System.out.println(json);
		MatcherAssert.assertThat(json.getAsString("counts"),
				Matchers.containsString("1, 1"));
	}

	@Test
	public void testGetBadInterval() {
		this.metricsCacheService.updateAllMetrics();
		JSONObject json =
				this.metricsCacheService.getScansByPeriod(CodeScanType.PULL_REQUEST, "foobar");
		MatcherAssert.assertThat(json.getAsString("error"),
				Matchers.containsString("Unknown time period"));
	}

	@Test
	public void testGetEmptyMetrics() {
		JSONObject json =
				this.metricsCacheService.getScansByPeriod(CodeScanType.PULL_REQUEST, "last-week");
		MatcherAssert.assertThat(json.getAsString("error"),
				Matchers.containsString("Null metric for that period"));
	}

	@Test
	public void testPauseUnpause() throws InterruptedException {
		this.metricsCacheService.pause();
		MatcherAssert.assertThat(this.metricsCacheService.isMetricsCacheReady(), Matchers.is(false));
		new Thread(() -> {
			this.metricsCacheService.updateAllMetrics();
		}).start();
		MatcherAssert.assertThat(this.metricsCacheService.isMetricsCacheReady(), Matchers.is(false));
		this.metricsCacheService.resume();
		Thread.sleep(1000);
		MatcherAssert.assertThat(this.metricsCacheService.isMetricsCacheReady(), Matchers.is(true));
	}

	@Test
	public void testGetScanCount() {
		BDDMockito.when(mockPrScanResultService.countScans()).thenReturn(2L);
		this.metricsCacheService.updateAllMetrics();
		Assertions.assertEquals(2, this.metricsCacheService.getScanCount(CodeScanType.PULL_REQUEST));
		Assertions.assertEquals(0, this.metricsCacheService.getScanCount(CodeScanType.UPLOAD));
	}

	@Test
	public void testGetViolationCount() {
		BDDMockito.when(mockPrScanResultService.countViolations()).thenReturn(2L);
		this.metricsCacheService.updateAllMetrics();
		Assertions.assertEquals(2, this.metricsCacheService.getViolationCount(CodeScanType.PULL_REQUEST));
		Assertions.assertEquals(0, this.metricsCacheService.getViolationCount(CodeScanType.UPLOAD));
	}

	@Test
	public void testGetAverageScanTime() {
		BDDMockito.when(mockPrScanResultService.getAverageTime()).thenReturn(2.0);
		this.metricsCacheService.updateAllMetrics();
		Assertions.assertEquals(2.0,
				this.metricsCacheService.getAverageScanTime(CodeScanType.PULL_REQUEST), 0.0);
		Assertions.assertEquals(0.0,
				this.metricsCacheService.getAverageScanTime(CodeScanType.UPLOAD), 0.0);
	}

	@Test
	public void testGetAverageScanTimeStringMS() {
		BDDMockito.when(mockPrScanResultService.getAverageTime()).thenReturn(2.0);
		this.metricsCacheService.updateAllMetrics();
		Assertions.assertEquals("2 ms",
				this.metricsCacheService.getAverageScanTimeString(CodeScanType.PULL_REQUEST));
	}

	@Test
	public void testGetAverageScanTimeStringS() {
		BDDMockito.when(mockPrScanResultService.getAverageTime()).thenReturn(2.0 * 1000);
		this.metricsCacheService.updateAllMetrics();
		Assertions.assertEquals("2.00 s",
				this.metricsCacheService.getAverageScanTimeString(CodeScanType.PULL_REQUEST));
	}

	@Test
	public void testGetAverageScanTimeStringMins() {
		BDDMockito.when(mockPrScanResultService.getAverageTime()).thenReturn(2.0 * 1000 * 60);
		this.metricsCacheService.updateAllMetrics();
		Assertions.assertEquals("2.00 mins",
				this.metricsCacheService.getAverageScanTimeString(CodeScanType.PULL_REQUEST));
	}
}
