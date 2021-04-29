package com.tracelink.appsec.watchtower.core.scan.scm.pr.entity;

import java.nio.file.Path;

import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
import javax.persistence.Table;

import com.tracelink.appsec.watchtower.core.report.ScanViolation;
import com.tracelink.appsec.watchtower.core.scan.AbstractViolationEntity;

/**
 * Violation Entity class for Pull Requests with join to {@linkplain PullRequestScanEntity}
 * 
 * @author csmith
 *
 */
@Entity
@Table(name = "pull_request_violations")
public class PullRequestViolationEntity extends
		AbstractViolationEntity<PullRequestScanEntity> {

	@ManyToOne(fetch = FetchType.EAGER)
	@JoinColumn(name = "scan_entity_id", nullable = false)
	private PullRequestScanEntity scan;

	public PullRequestViolationEntity() {
		super();
	}

	public PullRequestViolationEntity(ScanViolation sv, Path workingDirectory) {
		super(sv, workingDirectory);
	}

	@Override
	public PullRequestScanEntity getScan() {
		return scan;
	}

	@Override
	public void setScan(PullRequestScanEntity scan) {
		this.scan = scan;
	}

}
