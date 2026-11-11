package com.tracelink.appsec.watchtower.core.cwe;

import java.util.Collection;
import java.util.List;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

/**
 * Reads and writes the stored CWE catalog. Replacing the catalog is one transaction, so readers see the old
 * set or the new set and never a mix; a failed refresh only records its reason.
 */
@Service
public class CweCatalogStore {
	private static final int MAX_ERROR = 255;

	private final CweEntryRepository entries;
	private final CweCatalogMetaRepository meta;

	public CweCatalogStore(CweEntryRepository entries, CweCatalogMetaRepository meta) {
		this.entries = entries;
		this.meta = meta;
	}

	/** @return the status row; a fresh "never loaded" row if the table has none yet */
	@Transactional(readOnly = true)
	public CweCatalogMetaEntity meta() {
		return meta.findById(CweCatalogMetaEntity.ROW_ID).orElseGet(CweCatalogMetaEntity::new);
	}

	@Transactional(readOnly = true)
	public List<CweEntry> all() {
		return entries.findAll().stream().map(CweEntryEntity::toEntry).toList();
	}

	/** Swaps the whole catalog for {@code fresh} and records the release it came from. */
	@Transactional
	public void replace(Collection<CweEntry> fresh, CweCatalogClient.Version version, String actor, long now) {
		entries.deleteAllInBatch();
		entries.saveAll(fresh.stream().map(entry -> new CweEntryEntity(entry, now)).toList());
		CweCatalogMetaEntity row = meta.findById(CweCatalogMetaEntity.ROW_ID).orElseGet(CweCatalogMetaEntity::new);
		row.succeeded(version.version(), version.date(), fresh.size(), now, actor);
		meta.save(row);
	}

	/** Records why the last refresh failed; the stored catalog is not touched. */
	@Transactional(propagation = Propagation.REQUIRES_NEW)
	public void recordFailure(String error) {
		CweCatalogMetaEntity row = meta.findById(CweCatalogMetaEntity.ROW_ID).orElseGet(CweCatalogMetaEntity::new);
		row.failed(error == null ? "The update failed" : error.substring(0, Math.min(error.length(), MAX_ERROR)));
		meta.save(row);
	}
}
