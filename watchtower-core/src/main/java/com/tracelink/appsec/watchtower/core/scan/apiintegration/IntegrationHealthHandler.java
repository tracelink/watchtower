package com.tracelink.appsec.watchtower.core.scan.apiintegration;

import java.util.List;
import java.util.function.Consumer;

import org.springframework.stereotype.Component;

import com.tracelink.appsec.watchtower.core.job.AsyncJobEntity;
import com.tracelink.appsec.watchtower.core.job.AsyncJobHandler;
import com.tracelink.appsec.watchtower.core.job.AsyncJobType;

/**
 * Tests every integration's connection, off the request thread, through the queue. The
 * schedule queues it when a check is due (see RepoScanTriggers), so one pod does it.
 *
 * @author Watchtower
 */
@Component
public class IntegrationHealthHandler implements AsyncJobHandler {

	/** One check job at a time across the cluster. */
	public static final String DEDUP_KEY = "integration-health";

	private final ApiIntegrationService integrations;

	private final IntegrationHealthService health;

	public IntegrationHealthHandler(ApiIntegrationService integrations,
			IntegrationHealthService health) {
		this.integrations = integrations;
		this.health = health;
	}

	@Override
	public AsyncJobType type() {
		return AsyncJobType.INTEGRATION_HEALTH;
	}

	@Override
	public String handle(AsyncJobEntity job, Consumer<String> progress) {
		List<ApiIntegrationEntity> all = integrations.getAllSettings();
		// The failing names go into the note so the Queue tab can say which one failed.
		List<String> failing = health.checkAllFailing(all);
		progress.accept(all.size() + " checked, " + failing.size() + " failing"
				+ (failing.isEmpty() ? "" : ": " + String.join(", ", failing)));
		return null;
	}
}
