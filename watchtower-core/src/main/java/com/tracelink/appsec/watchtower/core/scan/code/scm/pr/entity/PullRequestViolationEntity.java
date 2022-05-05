package com.tracelink.appsec.watchtower.core.scan.code.scm.pr.entity;

import java.nio.file.Path;

import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
import javax.persistence.Table;

import com.tracelink.appsec.watchtower.core.scan.code.AbstractCodeScanViolationEntity;
import com.tracelink.appsec.watchtower.core.scan.code.report.CodeScanViolation;

/**
 * Violation Entity class for Pull Requests with join to {@linkplain PullRequestScanEntity}
 * 
 * @author csmith
 *
 */
@Entity
@Table(name = "pull_request_violations")
public class PullRequestViolationEntity extends
		AbstractCodeScanViolationEntity<PullRequestScanEntity> {

	@ManyToOne(fetch = FetchType.EAGER)
	@JoinColumn(name = "scan_entity_id", nullable = false)
	private PullRequestScanEntity scan;

	public PullRequestViolationEntity() {
		super();
	}

	public PullRequestViolationEntity(CodeScanViolation sv, Path workingDirectory) {
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
