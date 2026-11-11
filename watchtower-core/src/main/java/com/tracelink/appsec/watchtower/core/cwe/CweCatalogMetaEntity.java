package com.tracelink.appsec.watchtower.core.cwe;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

/** The one row (id 1) saying which CWE release is stored and how the last refresh ended. */
@Entity
@Table(name = "cwe_catalog_meta")
public class CweCatalogMetaEntity {
	/** Refresh outcomes. {@code NEVER} until the first successful refresh. */
	public static final String NEVER = "NEVER", OK = "OK", FAILED = "FAILED";
	public static final int ROW_ID = 1;

	@Id
	@Column(name = "meta_id")
	private int id = ROW_ID;
	@Column(name = "content_version", length = 16)
	private String contentVersion;
	@Column(name = "release_date", length = 16)
	private String releaseDate;
	@Column(name = "entry_count", nullable = false)
	private int entryCount;
	@Column(name = "refresh_status", length = 16, nullable = false)
	private String refreshStatus = NEVER;
	@Column(name = "last_error", length = 255)
	private String lastError;
	@Column(name = "fetched_at")
	private Long fetchedAt;
	@Column(name = "refreshed_by", length = 255)
	private String refreshedBy;

	public String getContentVersion() { return contentVersion; }
	public String getReleaseDate() { return releaseDate; }
	public int getEntryCount() { return entryCount; }
	public String getRefreshStatus() { return refreshStatus; }
	public String getLastError() { return lastError; }
	public Long getFetchedAt() { return fetchedAt; }
	public String getRefreshedBy() { return refreshedBy; }

	/** Records a successful refresh. */
	void succeeded(String version, String date, int count, long now, String actor) {
		this.contentVersion = version;
		this.releaseDate = date;
		this.entryCount = count;
		this.refreshStatus = OK;
		this.lastError = null;
		this.fetchedAt = now;
		this.refreshedBy = actor;
	}

	/** Records a failed refresh and leaves the stored catalog as it was. */
	void failed(String error) {
		this.refreshStatus = FAILED;
		this.lastError = error;
	}
}
