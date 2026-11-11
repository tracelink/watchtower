package com.tracelink.appsec.watchtower.core.scan.code;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Objects;

import jakarta.persistence.Column;
import jakarta.persistence.Embedded;
import jakarta.persistence.MappedSuperclass;
import jakarta.persistence.Transient;

import com.tracelink.appsec.watchtower.core.scan.AbstractScanEntity;
import com.tracelink.appsec.watchtower.core.scan.AbstractScanViolationEntity;
import com.tracelink.appsec.watchtower.core.rule.RuleExecutionIdentity;
import com.tracelink.appsec.watchtower.core.rule.RuleIdentityMetadata;
import com.tracelink.appsec.watchtower.core.scan.code.report.CodeScanViolation;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.entity.PullRequestScanEntity;

/**
 * Entity description for a violation entity.
 *
 * @param <S> a type describing the associated Scan
 * @author csmith
 */
@MappedSuperclass
public abstract class AbstractCodeScanViolationEntity<S extends AbstractScanEntity<?, ?>>
		extends AbstractScanViolationEntity<S>
		implements Comparable<AbstractCodeScanViolationEntity<S>> {

	@Column(name = "line_number")
	private int lineNum;

	@Column(name = "file_path")
	private String fileName;

	@Embedded
	private RuleIdentityMetadata ruleIdentity = new RuleIdentityMetadata();
	@Column(name = "effective_blocking")
	private Boolean effectiveBlocking;
	@Column(name = "engine_fingerprint", length = 64)
	private String engineFingerprint;

	@Column(name = "new_finding")
	private Boolean isNewViolation;

	@Column(name = "final_blocking")
	private Boolean blocking;

	@Transient
	// Rule messages remain transient; this metadata does not persist repository source.
	private String message;

	/**
	 * Copy the data from the {@linkplain CodeScanViolation} into this entity
	 * 
	 * @param sv         the scan violation
	 * @param workingDir the path to the working directory for the violation
	 */
	public AbstractCodeScanViolationEntity(CodeScanViolation sv, Path workingDir) {
		setFileName(relativizeFileName(workingDir, sv.getFileName()));
		setLineNum(sv.getLineNum());
		setSeverity(sv.getSeverity());
		setViolationName(sv.getViolationName());
		setMessage(sv.getMessage());
		setRuleIdentity(sv.getRuleIdentity());
		setEffectiveBlocking(sv.getEffectiveBlocking());
		blocking = sv.getEffectiveBlocking();
		engineFingerprint = sv.getEngineFingerprint();
	}

	public RuleExecutionIdentity getRuleIdentity() { return ruleIdentity == null ? null : ruleIdentity.toIdentity(); }
	public void setRuleIdentity(RuleExecutionIdentity identity) { ruleIdentity = new RuleIdentityMetadata(identity); }
	/** Retain partial historical provenance even when its engine/module is unknown. */
	public Long getExecutionRuleId() { return ruleIdentity == null ? null : ruleIdentity.getRuleId(); }
	public String getRuleRevision() { return ruleIdentity == null ? null : ruleIdentity.getRevision(); }
	public Boolean getEffectiveBlocking() { return effectiveBlocking; }
	public void setEffectiveBlocking(Boolean blocking) { effectiveBlocking = blocking; }
	public String getEngineFingerprint() { return engineFingerprint; }
	public Boolean getNewFinding() { return isNewViolation; }
	public Boolean getFinalBlocking() { return blocking; }

	public AbstractCodeScanViolationEntity() {
		// Default constructor
	}

	public abstract S getScan();

	public abstract void setScan(S scan);

	public int getLineNum() {
		return lineNum;
	}

	public void setLineNum(int lineNum) {
		this.lineNum = lineNum;
	}

	public String getFileName() {
		return fileName;
	}

	public void setFileName(String fileName) {
		this.fileName = fileName;
	}

	public boolean isNewViolation() {
		return Boolean.TRUE.equals(this.isNewViolation);
	}

	public void setNewViolation(boolean isNewViolation) {
		this.isNewViolation = isNewViolation;
	}

	public String getMessage() {
		return this.message;
	}

	public void setMessage(String message) {
		this.message = message;
	}

	public boolean isBlocking() {
		return Boolean.TRUE.equals(blocking);
	}

	public void setBlocking(boolean blocking) {
		this.blocking = blocking;
	}

	private String relativizeFileName(Path workingDir, String oldFileName) {
		Path rel = workingDir.toAbsolutePath().relativize(Paths.get(oldFileName));
		return rel.normalize().toString();
	}

	@Override
	public int compareTo(AbstractCodeScanViolationEntity<S> o) {
		int compare =
				Integer.compare(o.getSeverity().getPriority(), this.getSeverity().getPriority());
		if (compare == 0) {
			compare = this.getFileName().compareTo(o.getFileName());
		}
		return compare;
	}

	@Override
	public boolean equals(Object obj) {
		if (obj instanceof AbstractCodeScanViolationEntity) {
			AbstractCodeScanViolationEntity<PullRequestScanEntity> temp = (AbstractCodeScanViolationEntity<PullRequestScanEntity>) obj;
			if (this.getId() == temp.getId() &&
					this.getViolationName().equals(temp.getViolationName()) &&
					this.lineNum == temp.lineNum &&
					this.fileName.equals(temp.fileName) &&
					Objects.equals(this.isNewViolation, temp.isNewViolation) &&
					Objects.equals(this.blocking, temp.blocking) &&
					Objects.equals(this.message, temp.message))
				return true;
		}
		return false;
	}

	@Override
	public int hashCode() {
		return Objects.hash(getId(), getViolationName(), lineNum, fileName, isNewViolation, blocking,
				message);
	}

}
