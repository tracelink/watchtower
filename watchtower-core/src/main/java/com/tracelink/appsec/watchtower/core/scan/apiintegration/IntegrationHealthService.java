package com.tracelink.appsec.watchtower.core.scan.apiintegration;

import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

/**
 * Whether each integration can still connect: the result of its last check (the Test button,
 * a catalog sync, or the 6-hourly check job), stored on the integration. An integration whose
 * last check, within a day, failed is "failing".
 *
 * @author Watchtower
 */
@Service
public class IntegrationHealthService {

	private static final Logger LOG = LoggerFactory.getLogger(IntegrationHealthService.class);

	static final long CHECK_EVERY_MILLIS = Duration.ofHours(6).toMillis();

	static final long FAILING_WITHIN_MILLIS = Duration.ofDays(1).toMillis();

	static final int MAX_ERROR = 500;

	/** user:password@ in a URL, so an exception message never stores a credential. */
	private static final Pattern URL_CREDENTIALS =
			Pattern.compile("(?i)([a-z][a-z0-9+.-]*://)[^/\\s:@]+:[^/\\s@]+@");

	/** An HTTP authorization scheme and its credential. */
	private static final Pattern AUTH_SCHEMES =
			Pattern.compile("(?i)\\b(bearer|basic|token)\\s+[A-Za-z0-9._~+/=-]+");

	/** key=value, key: value or "key":"value" pairs whose key names a secret. */
	private static final Pattern SECRET_PAIRS = Pattern.compile(
			"(?i)((?:password|passwd|secret|[a-z_]*token|auth|api[_-]?key|authorization)"
					+ "[\"']?\\s*[=:]\\s*[\"']?)[^\\s,;&\"']+");

	private final ApiIntegrationRepository repository;

	private final Clock clock;

	@Autowired
	public IntegrationHealthService(ApiIntegrationRepository repository) {
		this(repository, Clock.systemUTC());
	}

	IntegrationHealthService(ApiIntegrationRepository repository, Clock clock) {
		this.repository = repository;
		this.clock = clock;
	}

	/**
	 * Records a connection check.
	 *
	 * @param apiLabel the integration
	 * @param ok       whether it connected
	 * @param error    why not, if it did not; credentials are stripped and it is cut to
	 *                 {@value #MAX_ERROR} characters
	 */
	public void record(String apiLabel, boolean ok, String error) {
		repository.recordHealth(apiLabel, clock.millis(), ok, ok ? null : clean(error));
	}

	/**
	 * Tests one integration's connection and records the result.
	 *
	 * @return true if it connected
	 */
	public boolean check(ApiIntegrationEntity integration) {
		try {
			integration.createApi().testClientConnection();
			record(integration.getApiLabel(), true, null);
			return true;
		} catch (IllegalStateException | NullPointerException e) {
			// Watchtower's own fault, not the provider's: say so instead of blaming the provider
			LOG.warn("Connection check of {} couldn't run", integration.getApiLabel(), e);
			record(integration.getApiLabel(), false,
					IntegrationPresentation.COULD_NOT_RUN + e.getMessage());
			return false;
		} catch (ApiIntegrationException | RuntimeException e) {
			LOG.warn("Connection check of {} failed: {}", integration.getApiLabel(),
					clean(e.getMessage()));
			record(integration.getApiLabel(), false, e.getMessage());
			return false;
		}
	}

	/**
	 * Tests every integration.
	 *
	 * @return the ones that failed, by name and provider, e.g. "Example (Amazon ECR)"
	 */
	public List<String> checkAllFailing(List<ApiIntegrationEntity> integrations) {
		List<String> failing = new ArrayList<>();
		for (ApiIntegrationEntity integration : integrations) {
			if (!check(integration)) {
				ApiType type = integration.getApiType();
				failing.add(type == null ? integration.getApiLabel()
						: integration.getApiLabel() + " (" + type.getTypeName() + ")");
			}
		}
		return List.copyOf(failing);
	}

	/**
	 * @return true if some integration was never checked, or not in the last six hours
	 */
	public boolean isCheckDue(List<ApiIntegrationEntity> integrations) {
		long dueBefore = clock.millis() - CHECK_EVERY_MILLIS;
		return integrations.stream().anyMatch(i -> i.getHealthCheckedAt() == null
				|| i.getHealthCheckedAt() < dueBefore);
	}

	/**
	 * @return true if the integration's last check failed, and that check was within a day
	 */
	public boolean isFailing(ApiIntegrationEntity integration) {
		return Boolean.FALSE.equals(integration.getHealthOk())
				&& integration.getHealthCheckedAt() != null
				&& clock.millis() - integration.getHealthCheckedAt() <= FAILING_WITHIN_MILLIS;
	}

	static String clean(String error) {
		// Cut first: the patterns then always run on a short text
		String text = StringUtils.left(StringUtils.defaultIfBlank(error, "The connection failed"),
				MAX_ERROR * 4);
		text = URL_CREDENTIALS.matcher(text).replaceAll("$1");
		text = AUTH_SCHEMES.matcher(text).replaceAll("$1 [hidden]");
		text = SECRET_PAIRS.matcher(text).replaceAll("$1[hidden]");
		return StringUtils.abbreviate(StringUtils.normalizeSpace(text), MAX_ERROR);
	}
}
