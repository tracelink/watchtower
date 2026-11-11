package com.tracelink.appsec.watchtower.core.scan.apiintegration;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.BDDMockito;
import org.mockito.Mockito;

import com.tracelink.appsec.watchtower.core.scan.IWatchtowerApi;
import com.tracelink.appsec.watchtower.core.scan.code.scm.api.IScmApi;
import com.tracelink.appsec.watchtower.core.scan.code.scm.api.bb.BBCloudIntegrationEntity;

public class IntegrationHealthServiceTest {

	private static final long NOW = 1_800_000_000_000L;

	private static final long HOUR = 3_600_000L;

	private ApiIntegrationRepository repository;

	private IntegrationHealthService health;

	@BeforeEach
	public void setup() {
		repository = Mockito.mock(ApiIntegrationRepository.class);
		health = new IntegrationHealthService(repository,
				Clock.fixed(Instant.ofEpochMilli(NOW), ZoneOffset.UTC));
	}

	@Test
	public void errorsAreStoredWithoutCredentialsAndCut() {
		health.record("bb", false, "GET https://bot:s3cret@api.bitbucket.org/2.0 failed,"
				+ " token=abc123 password: hunter2 " + "x".repeat(600));

		BDDMockito.verify(repository).recordHealth(BDDMockito.eq("bb"), BDDMockito.eq(NOW),
				BDDMockito.eq(false), BDDMockito.argThat(error -> error.length() <= 500
						&& error.startsWith("GET https://api.bitbucket.org/2.0 failed,")
						&& error.contains("token=[hidden]")
						&& error.contains("password: [hidden]")
						&& !error.contains("s3cret") && !error.contains("hunter2")));
	}

	@Test
	public void authorizationHeadersAndJsonSecretsAreHidden() {
		String cleaned = IntegrationHealthService.clean("Authorization: Bearer eyJhbGciOi.abc"
				+ " then Basic dXNlcjpwYXNz and {\"password\":\"hunter2\",\"access_token\":\"tok9\"}");
		Assertions.assertFalse(cleaned.contains("eyJhbGciOi"), cleaned);
		Assertions.assertFalse(cleaned.contains("dXNlcjpwYXNz"), cleaned);
		Assertions.assertFalse(cleaned.contains("hunter2"), cleaned);
		Assertions.assertFalse(cleaned.contains("tok9"), cleaned);
		Assertions.assertTrue(IntegrationHealthService.clean("x".repeat(100_000)).length() <= 500);
	}

	@Test
	public void aSuccessfulCheckClearsTheError() {
		health.record("bb", true, "ignored");
		BDDMockito.verify(repository).recordHealth("bb", NOW, true, null);
	}

	@Test
	public void checkTestsTheConnectionAndRecordsEitherWay() throws Exception {
		ApiIntegrationEntity ok = integration("ok", null, null);
		ApiIntegrationEntity broken = Mockito.mock(ApiIntegrationEntity.class);
		IWatchtowerApi brokenApi = Mockito.mock(IWatchtowerApi.class);
		BDDMockito.when(broken.getApiLabel()).thenReturn("broken");
		BDDMockito.when(broken.getApiType()).thenReturn(ApiType.ECR);
		BDDMockito.when(broken.createApi()).thenReturn(brokenApi);
		BDDMockito.willThrow(new ApiIntegrationException("401 Unauthorized")).given(brokenApi)
				.testClientConnection();

		Assertions.assertEquals(List.of("broken (Amazon ECR)"), health.checkAllFailing(List.of(ok, broken)));
		BDDMockito.verify(repository).recordHealth("ok", NOW, true, null);
		BDDMockito.verify(repository).recordHealth("broken", NOW, false, "401 Unauthorized");
	}

	@Test
	public void aCheckThatCouldNotRunIsRecordedAsWatchtowersOwnError() throws Exception {
		ApiIntegrationEntity ecr = Mockito.mock(ApiIntegrationEntity.class);
		IWatchtowerApi api = Mockito.mock(IWatchtowerApi.class);
		BDDMockito.when(ecr.getApiLabel()).thenReturn("Example");
		BDDMockito.when(ecr.createApi()).thenReturn(api);
		BDDMockito.willThrow(new IllegalStateException("No current ServletRequestAttributes"))
				.given(api).testClientConnection();

		Assertions.assertFalse(health.check(ecr));
		BDDMockito.verify(repository).recordHealth(BDDMockito.eq("Example"), BDDMockito.eq(NOW),
				BDDMockito.eq(false), BDDMockito.startsWith(IntegrationPresentation.COULD_NOT_RUN));
	}

	@Test
	public void failingMeansTheLastCheckFailedWithinADay() {
		Assertions.assertTrue(health.isFailing(integration("a", NOW - 23 * HOUR, false)));
		Assertions.assertFalse(health.isFailing(integration("b", NOW - 25 * HOUR, false)),
				"an old failure is no longer shown as failing");
		Assertions.assertFalse(health.isFailing(integration("c", NOW - HOUR, true)));
		Assertions.assertFalse(health.isFailing(integration("d", null, null)));
	}

	@Test
	public void aCheckIsDueEverySixHoursOrWhenNeverChecked() {
		Assertions.assertFalse(health.isCheckDue(List.of(integration("a", NOW - 5 * HOUR,
				true))));
		Assertions.assertTrue(health.isCheckDue(List.of(integration("a", NOW - 7 * HOUR,
				true))));
		Assertions.assertTrue(health.isCheckDue(List.of(integration("a", NOW - HOUR, true),
				integration("b", null, null))));
		Assertions.assertFalse(health.isCheckDue(List.of()));
	}

	private static ApiIntegrationEntity integration(String label, Long checkedAt, Boolean ok) {
		BBCloudIntegrationEntity integration = Mockito.spy(new BBCloudIntegrationEntity());
		integration.setApiLabel(label);
		integration.setHealth(checkedAt, ok, null);
		Mockito.doReturn(Mockito.mock(IScmApi.class)).when(integration).createApi();
		return integration;
	}
}
