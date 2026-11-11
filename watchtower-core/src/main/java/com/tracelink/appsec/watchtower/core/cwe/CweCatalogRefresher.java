package com.tracelink.appsec.watchtower.core.cwe;

import java.io.IOException;
import java.time.Clock;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Consumer;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

/**
 * Brings the stored CWE catalog up to date from MITRE: asks which release is current, lists the weaknesses,
 * downloads them in small batches and swaps the stored set in one step. Any failure leaves the old catalog in
 * place and records a reason that is safe to show.
 */
@Service
public class CweCatalogRefresher {
	private static final org.slf4j.Logger LOG = org.slf4j.LoggerFactory.getLogger(CweCatalogRefresher.class);
	/** Weaknesses per request: about 1 MB of answer each, far below the client's size cap. */
	static final int BATCH_SIZE = 20;
	/** An update may not drop more than a fifth of what is stored. */
	static final double KEEP_AT_LEAST = 0.8;
	/** A load may not hold fewer than half of what the release says it contains. */
	static final double RELEASE_AT_LEAST = 0.5;

	private final CweCatalogClient client;
	private final CweCatalogStore store;
	private final Clock clock;

	@Autowired
	public CweCatalogRefresher(CweCatalogClient client, CweCatalogStore store) {
		this(client, store, Clock.systemUTC());
	}

	CweCatalogRefresher(CweCatalogClient client, CweCatalogStore store, Clock clock) {
		this.client = client;
		this.store = store;
		this.clock = clock;
	}

	/**
	 * @param actor    who asked for the update
	 * @param force    download again even when the stored release is already the current one
	 * @param progress receives short progress notes
	 * @return a short sentence for the queue view
	 * @throws IOException if the catalog could not be updated; the message is safe to show
	 */
	public String refresh(String actor, boolean force, Consumer<String> progress) throws IOException {
		try {
			return doRefresh(actor, force, progress);
		} catch (IOException e) {
			store.recordFailure(e.getMessage());
			throw e;
		} catch (RuntimeException e) {
			LOG.error("CWE catalog update failed", e);
			String safe = "The update failed unexpectedly; see the server log";
			store.recordFailure(safe);
			throw new IOException(safe);
		}
	}

	private String doRefresh(String actor, boolean force, Consumer<String> progress) throws IOException {
		CweCatalogClient.Version version = client.version();
		CweCatalogMetaEntity current = store.meta();
		boolean stored = CweCatalogMetaEntity.OK.equals(current.getRefreshStatus()) && current.getEntryCount() > 0;
		if (!force && stored && version.version().equals(current.getContentVersion())) {
			return "Already current: CWE " + version.version();
		}
		Set<Integer> ids = listIds(progress);
		Map<Integer, CweEntry> fetched = download(ids, progress);
		refuseIfTooSmall(fetched.size(), version, stored ? current.getEntryCount() : 0);
		store.replace(fetched.values(), version, actor, clock.millis());
		return "CWE " + version.version() + ": " + fetched.size() + " weaknesses";
	}

	private Set<Integer> listIds(Consumer<String> progress) throws IOException {
		List<Integer> pillars = client.topLevelIds();
		Set<Integer> ids = new LinkedHashSet<>(pillars);
		int done = 0;
		for (int pillar : pillars) {
			progress.accept("Listing weaknesses " + (++done) + " of " + pillars.size());
			ids.addAll(client.descendantIds(pillar));
		}
		return ids;
	}

	private Map<Integer, CweEntry> download(Set<Integer> ids, Consumer<String> progress) throws IOException {
		List<Integer> all = new ArrayList<>(ids);
		Map<Integer, CweEntry> fetched = new LinkedHashMap<>();
		for (int from = 0; from < all.size(); from += BATCH_SIZE) {
			progress.accept("Downloading " + from + " of " + all.size());
			for (CweEntry entry : client.weaknesses(all.subList(from, Math.min(from + BATCH_SIZE, all.size())))) {
				fetched.put(entry.id(), entry);
			}
		}
		return fetched;
	}

	private static void refuseIfTooSmall(int count, CweCatalogClient.Version version, int stored) throws IOException {
		if (count < version.weaknesses() * RELEASE_AT_LEAST || (stored > 0 && count < stored * KEEP_AT_LEAST)) {
			throw new IOException("MITRE's answer holds fewer weaknesses (" + count
					+ ") than expected, so the stored catalog was kept");
		}
	}
}
