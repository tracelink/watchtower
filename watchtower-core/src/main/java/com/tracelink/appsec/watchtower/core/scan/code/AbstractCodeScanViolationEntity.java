package com.tracelink.appsec.watchtower.core.scan.code;

import java.nio.file.Path;
import java.nio.file.Paths;

import javax.persistence.Column;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.MappedSuperclass;
import javax.persistence.Transient;

import com.tracelink.appsec.watchtower.core.scan.AbstractScanEntity;
import com.tracelink.appsec.watchtower.core.scan.AbstractScanViolationEntity;
import com.tracelink.appsec.watchtower.core.scan.code.report.CodeScanViolation;

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

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	@Column(name = "vio_entity_id")
	private long id;

	@Column(name = "violation_name")
	private String violationName;

	@Column(name = "line_number")
	private int lineNum;

	@Column(name = "severity_name")
	private String severity;

	@Column(name = "severity_value")
	private int severityValue;

	@Column(name = "file_path")
	private String fileName;

	///////////////////////////////////////
	// The following are not saved to the
	// database as they are only important
	// at the time of scanning and reporting
	///////////////////////////////////////

	@Transient
	private boolean isNewViolation;

	@Transient
	private boolean blocking;

	@Transient
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
		setSeverityValue(sv.getSeverityValue());
		setViolationName(sv.getViolationName());
		setMessage(sv.getMessage());
	}

	public AbstractCodeScanViolationEntity() {
		// Default constructor
	}

	public abstract S getScan();

	public abstract void setScan(S scan);

	public String getViolationName() {
		return violationName;
	}

	public void setViolationName(String violationName) {
		this.violationName = violationName;
	}

	public int getLineNum() {
		return lineNum;
	}

	public void setLineNum(int lineNum) {
		this.lineNum = lineNum;
	}

	public String getSeverity() {
		return severity;
	}

	public void setSeverity(String severity) {
		this.severity = severity;
	}

	public int getSeverityValue() {
		return severityValue;
	}

	public void setSeverityValue(int severityValue) {
		this.severityValue = severityValue;
	}

	public String getFileName() {
		return fileName;
	}

	public void setFileName(String fileName) {
		this.fileName = fileName;
	}

	public boolean isNewViolation() {
		return this.isNewViolation;
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
		return blocking;
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
		int compare = Integer.compare(o.getSeverityValue(), this.getSeverityValue());
		if (compare == 0) {
			compare = this.getFileName().compareTo(o.getFileName());
		}
		return compare;
	}

}
