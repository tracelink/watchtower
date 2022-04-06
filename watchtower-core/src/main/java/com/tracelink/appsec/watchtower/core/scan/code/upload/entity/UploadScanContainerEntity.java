package com.tracelink.appsec.watchtower.core.scan.code.upload.entity;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.List;

import javax.persistence.CascadeType;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.OneToOne;
import javax.persistence.Table;

import com.tracelink.appsec.watchtower.core.scan.code.AbstractScanContainer;

/**
 * Container Entity class for Uploads with reverse join to {@linkplain UploadScanEntity}
 * 
 * @author csmith
 *
 */
@Entity
@Table(name = "upload_container")
public class UploadScanContainerEntity extends AbstractScanContainer<UploadScanEntity> {

	@Column(name = "name")
	private String name;

	@Column(name = "submitter")
	private String submitter;

	@Column(name = "ticket")
	private String ticket;

	@Column(name = "ruleset")
	private String ruleSetName;

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

	public void setZipPath(Path filePath) {
		fileLocation = filePath.toAbsolutePath().toString();
	}

	public Path getZipPath() {
		return Paths.get(fileLocation);
	}

	public UploadScanEntity getLatestUploadScan() {
		return getScans() == null ? null : getScans().get(0);
	}

	@Override
	public List<UploadScanEntity> getScans() {
		return Arrays.asList(scan);
	}

}
