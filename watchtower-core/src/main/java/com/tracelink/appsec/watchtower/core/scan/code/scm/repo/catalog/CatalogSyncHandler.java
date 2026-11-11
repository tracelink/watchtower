package com.tracelink.appsec.watchtower.core.scan.code.scm.repo.catalog;

import java.time.Clock;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;
import java.util.stream.Stream;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.tracelink.appsec.watchtower.core.job.AsyncJobEntity;
import com.tracelink.appsec.watchtower.core.job.AsyncJobHandler;
import com.tracelink.appsec.watchtower.core.job.AsyncJobType;
import com.tracelink.appsec.watchtower.core.job.RetryLaterException;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.IntegrationHealthService;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetEntity;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetService;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.ApiIntegrationEntity;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.ApiIntegrationService;
import com.tracelink.appsec.watchtower.core.scan.code.scm.api.IScmApi;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.catalog.RepoCatalogDao.Catalog;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.catalog.RepoCatalogDao.CatalogRow;
import com.tracelink.appsec.watchtower.core.scan.presentation.PluralText;

/**
 * Refreshes one SCM integration's repositories in the catalog. Runs as a queued job because a
 * large workspace takes many API pages. Only after a complete listing are repositories that
 * were not listed disabled; a listing that stops early disables nothing.
 *
 * @author Watchtower
 */
@Component
public class CatalogSyncHandler implements AsyncJobHandler {

	private static final Logger LOG = LoggerFactory.getLogger(CatalogSyncHandler.class);

	private static final ObjectMapper MAPPER = new ObjectMapper();

	static final int RETRY_SECONDS = 15 * 60;

	private final ApiIntegrationService integrations;

	private final RulesetService rulesets;

	private final RepoCatalogDao catalog;

	private final IntegrationHealthService health;

	private final Clock clock;

	@Autowired
	public CatalogSyncHandler(ApiIntegrationService integrations, RulesetService rulesets,
			RepoCatalogDao catalog, IntegrationHealthService health) {
		this(integrations, rulesets, catalog, health, Clock.systemUTC());
	}

	CatalogSyncHandler(ApiIntegrationService integrations, RulesetService rulesets,
			RepoCatalogDao catalog, IntegrationHealthService health, Clock clock) {
		this.integrations = integrations;
		this.rulesets = rulesets;
		this.catalog = catalog;
		this.health = health;
		this.clock = clock;
	}

	@Override
	public AsyncJobType type() {
		return AsyncJobType.CATALOG_SYNC;
	}

	/**
	 * @param apiLabel the integration to sync
	 * @return the job payload naming it
	 */
	public static String payload(String apiLabel) {
		return MAPPER.createObjectNode().put("apiLabel", apiLabel).toString();
	}

	@Override
	public String handle(AsyncJobEntity job, Consumer<String> progress) throws Exception {
		JsonNode payload = MAPPER.readTree(job.getPayload());
		String apiLabel = payload.path("apiLabel").asText("");
		ApiIntegrationEntity integration = integrations.findByLabel(apiLabel);
		if (integration == null) {
			throw new IllegalStateException("Integration " + apiLabel + " no longer exists");
		}
		if (!(integration.createApi() instanceof IScmApi api)) {
			throw new IllegalStateException(apiLabel + " is not a source code integration");
		}
		long now = clock.millis();
		RulesetEntity defaultRuleset = rulesets.getDefaultRuleset();
		Long defaultRulesetId = defaultRuleset == null ? null : defaultRuleset.getId();
		Catalog existing = catalog.rows(apiLabel);
		Set<String> listed = new HashSet<>();
		AtomicInteger written = new AtomicInteger();
		boolean complete = api.listRepositories(page -> {
			page.stream().map(r -> RepoCatalogDao.nameKey(r.slug())).forEach(listed::add);
			written.addAndGet(catalog.upsertPage(apiLabel, page, existing.byKey(),
					defaultRulesetId, now));
			progress.accept(PluralText.count(listed.size(), "repository", "repositories") + " listed");
		});
		if (!complete) {
			health.record(apiLabel, false, "The repository listing stopped early");
			throw new RetryLaterException("The repository listing of " + apiLabel
					+ " stopped early; nothing was disabled", RETRY_SECONDS);
		}
		health.record(apiLabel, true, null);
		int disabled = disableUnlisted(apiLabel, listed, existing);
		LOG.info("Synced {}: {} repositories listed, {} added or changed, {} disabled",
				apiLabel, listed.size(), written.get(), disabled);
		progress.accept(PluralText.count(listed.size(), "repository", "repositories") + ", "
				+ written.get() + " changed, " + disabled + " gone");
		return null;
	}

	/**
	 * Disables what the listing no longer has, and duplicates of a listed repository under its
	 * display name (once stored by pull request webhooks), so plans stop scanning a name the
	 * SCM does not know.
	 *
	 * @param listed   the listed repositories' {@link RepoCatalogDao#nameKey}s
	 * @param existing the repositories before the sync, by the same key
	 */
	private int disableUnlisted(String apiLabel, Set<String> listed, Catalog existing) {
		if (listed.isEmpty()) {
			// An empty listing is far likelier to be a credential or permission problem than
			// a workspace with no repositories; never disable a whole integration on it
			LOG.warn("{} listed no repositories; not disabling any", apiLabel);
			return 0;
		}
		Stream<CatalogRow> unlisted = existing.byKey().entrySet().stream()
				.filter(entry -> !listed.contains(entry.getKey())).map(Map.Entry::getValue);
		List<Long> gone = Stream.concat(unlisted, existing.shadowed().stream())
				.filter(CatalogRow::enabled).map(CatalogRow::id).toList();
		return catalog.disable(gone);
	}
}
