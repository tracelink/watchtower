package com.tracelink.appsec.watchtower.core.scan.code.upload.entity;

import java.util.Arrays;
import java.util.List;

import jakarta.persistence.CascadeType;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.OneToOne;
import jakarta.persistence.Table;

import com.tracelink.appsec.watchtower.core.scan.AbstractScanContainerEntity;

/**
 * Container Entity class for Uploads with reverse join to {@linkplain UploadScanEntity}
 * 
 * @author csmith
 *
 */
@Entity
@Table(name = "upload_container")
public class UploadScanContainerEntity extends AbstractScanContainerEntity<UploadScanEntity> {

	@Column(name = "name")
	private String name;

	@Column(name = "submitter")
	private String submitter;

	@Column(name = "ticket")
	private String ticket;

	@Column(name = "ruleset")
	private String ruleSetName;

	// Column name predates S3 storage (item 3.4); it is a plain String, so no Flyway
	// migration was needed to store a scheme-prefixed storage key here instead of a
	// bare local file path - see UploadStorageLocation for the prefix scheme.
	@Column(name = "file_location")
	private String fileLocation;

	@OneToOne(fetch = FetchType.EAGER, mappedBy = "container", cascade = CascadeType.MERGE)
	private UploadScanEntity scan;

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	public String getSubmitter() {
		return submitter;
	}

	public void setSubmitter(String submitter) {
		this.submitter = submitter;
	}

	public void setTicket(String ticket) {
		this.ticket = ticket;
	}

	public String getTicket() {
		return ticket;
	}

	public void setRuleSet(String ruleSetName) {
		this.ruleSetName = ruleSetName;
	}

	public String getRuleSet() {
		return this.ruleSetName;
	}

	public void setStorageKey(String storageKey) {
		fileLocation = storageKey;
	}

	public String getStorageKey() {
		return fileLocation;
	}

	public UploadScanEntity getLatestUploadScan() {
		return getScans() == null ? null : getScans().get(0);
	}

	@Override
	public List<UploadScanEntity> getScans() {
		return Arrays.asList(scan);
	}

}
