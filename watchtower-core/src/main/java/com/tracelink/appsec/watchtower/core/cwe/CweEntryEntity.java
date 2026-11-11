package com.tracelink.appsec.watchtower.core.cwe;

import java.util.Arrays;
import java.util.List;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.PostLoad;
import jakarta.persistence.PostPersist;
import jakarta.persistence.Table;
import jakarta.persistence.Transient;

import org.springframework.data.domain.Persistable;

/** One stored CWE weakness (table {@code cwe_entry}). Rows are replaced as a set by a catalog refresh. */
@Entity
@Table(name = "cwe_entry")
public class CweEntryEntity implements Persistable<Integer> {
	@Id
	@Column(name = "cwe_id")
	private int id;
	@Column(name = "name", length = 255, nullable = false)
	private String name;
	@Column(name = "abstraction", length = 16)
	private String abstraction;
	@Column(name = "structure", length = 16)
	private String structure;
	@Column(name = "entry_status", length = 16)
	private String status;
	@Column(name = "mapping_usage", length = 32, nullable = false)
	private String usage;
	@Column(name = "description", length = 2000)
	private String description;
	@Column(name = "likelihood", length = 16)
	private String likelihood;
	@Column(name = "parent_ids", length = 255, nullable = false)
	private String parentIds;
	@Column(name = "updated_at", nullable = false)
	private long updatedAt;

	/** Rows are always inserted as a fresh set, so saving must not read each one first. */
	@Transient
	private boolean fresh = true;

	protected CweEntryEntity() {
	}

	public CweEntryEntity(CweEntry entry, long now) {
		this.id = entry.id();
		this.name = entry.name();
		this.abstraction = entry.abstraction();
		this.structure = entry.structure();
		this.status = entry.status();
		this.usage = entry.usage();
		this.description = entry.description();
		this.likelihood = entry.likelihood();
		this.parentIds = String.join(",", entry.parents().stream().map(String::valueOf).toList());
		this.updatedAt = now;
	}

	public CweEntry toEntry() {
		List<Integer> parents = parentIds == null || parentIds.isBlank() ? List.of()
				: Arrays.stream(parentIds.split(",")).map(Integer::valueOf).toList();
		return new CweEntry(id, name, abstraction, structure, status, usage, description, likelihood, parents);
	}

	@Override
	public Integer getId() {
		return id;
	}

	@Override
	public boolean isNew() {
		return fresh;
	}

	@PostLoad
	@PostPersist
	void stored() {
		fresh = false;
	}
}
