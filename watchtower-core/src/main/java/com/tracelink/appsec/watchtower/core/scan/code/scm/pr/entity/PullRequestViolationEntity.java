package com.tracelink.appsec.watchtower.core.scan.code.scm.pr.entity;

import java.nio.file.Path;

import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import jakarta.persistence.Column;

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

	/** Original scan-time bypass decision; null for legacy findings. */
	@Column(name = "bypassed")
	private Boolean bypassed;

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

	public boolean isBypassed() {
		return Boolean.TRUE.equals(bypassed);
	}

	public Boolean getBypassed() { return bypassed; }

	public void setBypassed(boolean bypassed) {
		this.bypassed = bypassed;
	}


	/** Rule names of manual-code-review matches start with this. */
	public static final String MCR_NAME_PREFIX = "MCR Match:";

	/** Whether a rule name marks a manual-code-review match rather than an ordinary finding. */
	public static boolean isMcrName(String ruleName) {
		return ruleName != null && ruleName.startsWith(MCR_NAME_PREFIX);
	}

	/** A manual-code-review match, reported separately from ordinary findings (MCR report). */
	public boolean isMcrMatch() {
		return isMcrName(getViolationName());
	}
}
