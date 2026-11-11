package com.tracelink.appsec.watchtower.core.cwe;

import java.util.function.Consumer;

import org.springframework.stereotype.Component;

import com.tracelink.appsec.watchtower.core.job.AsyncJobEntity;
import com.tracelink.appsec.watchtower.core.job.AsyncJobHandler;
import com.tracelink.appsec.watchtower.core.job.AsyncJobType;

/** Runs one CWE catalog update in the background. The payload is {@code force} or empty. */
@Component
public class CweCatalogJob implements AsyncJobHandler {
	/** Payload that downloads again even when the stored release is current. */
	public static final String FORCE = "force";

	private final CweCatalogRefresher refresher;

	public CweCatalogJob(CweCatalogRefresher refresher) {
		this.refresher = refresher;
	}

	@Override
	public AsyncJobType type() {
		return AsyncJobType.CWE_CATALOG_REFRESH;
	}

	@Override
	public String handle(AsyncJobEntity job, Consumer<String> progress) throws Exception {
		refresher.refresh(job.getCreatedBy(), FORCE.equals(job.getPayload()), progress);
		return null;
	}
}
