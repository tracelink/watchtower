package com.tracelink.appsec.watchtower.core.cwe;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

/** One weakness that matters in this installation, and how much (table {@code cwe_profile_entry}). */
@Entity
@Table(name = "cwe_profile_entry")
public class CweProfileEntryEntity {
	@Id
	@Column(name = "cwe_id")
	private int cweId;
	@Column(name = "priority", length = 16, nullable = false)
	private String priority;
	@Column(name = "note", length = 255)
	private String note;
	@Column(name = "added_by", length = 255, nullable = false)
	private String addedBy;
	@Column(name = "added_at", nullable = false)
	private long addedAt;

	protected CweProfileEntryEntity() {
	}

	public CweProfileEntryEntity(int cweId, CweProfilePriority priority, String note, String addedBy, long addedAt) {
		this.cweId = cweId;
		this.priority = priority.name();
		this.note = note;
		this.addedBy = addedBy;
		this.addedAt = addedAt;
	}

	void update(CweProfilePriority priority, String note) {
		this.priority = priority.name();
		this.note = note;
	}

	public int getCweId() { return cweId; }
	public CweProfilePriority getPriority() { return CweProfilePriority.valueOf(priority); }
	public String getNote() { return note; }
	public String getAddedBy() { return addedBy; }
	public long getAddedAt() { return addedAt; }
}
