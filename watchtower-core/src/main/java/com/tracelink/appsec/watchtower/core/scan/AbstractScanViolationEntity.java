package com.tracelink.appsec.watchtower.core.scan;

import jakarta.persistence.Column;
import jakarta.persistence.Convert;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.MappedSuperclass;

import com.tracelink.appsec.watchtower.core.rule.RulePriority;
import com.tracelink.appsec.watchtower.core.rule.RulePriority.RulePriorityConverter;

/**
 * Entity description for a violation entity.
 *
 * @param <S> a type describing the associated Scan
 * @author csmith
 */
@MappedSuperclass
public abstract class AbstractScanViolationEntity<S extends AbstractScanEntity<?, ?>> {

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	@Column(name = "vio_entity_id")
	private long id;

	@Column(name = "violation_name")
	private String violationName;

	@Column(name = "severity")
	@Convert(converter = RulePriorityConverter.class)
	private RulePriority severity;

	public abstract S getScan();

	public abstract void setScan(S scan);

	public long getId() {
		return id;
	}

	public String getViolationName() {
		return violationName;
	}

	public void setViolationName(String violationName) {
		this.violationName = violationName;
	}

	public RulePriority getSeverity() {
		return severity;
	}

	public void setSeverity(RulePriority severity) {
		this.severity = severity;
	}

}
