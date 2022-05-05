package com.tracelink.appsec.watchtower.core.scan;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.List;

import javax.persistence.Column;
import javax.persistence.Convert;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.MappedSuperclass;

import com.tracelink.appsec.watchtower.core.scan.ScanStatus.ScanStatusConverter;

/**
 * Entity description for the scan results entity.
 *
 * @param <C> a type describing the associated Container
 * @param <V> a type describing the associated Violation
 * @author csmith
 */
@MappedSuperclass
public abstract class AbstractScanEntity<C extends AbstractScanContainerEntity<?>, V extends AbstractScanViolationEntity<?>> {

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	@Column(name = "scan_entity_id")
	private long id;

	@Column(name = "submit_date")
	private long submitDate;

	@Column(name = "start_date")
	private long startDate;

	@Column(name = "end_date")
	private long endDate;

	@Column(name = "status")
	@Convert(converter = ScanStatusConverter.class)
	private ScanStatus status;

	@Column(name = "error")
	private String errorMessage;

	public long getId() {
		return id;
	}

	public abstract C getContainer();

	public abstract void setContainer(C container);

	public long getSubmitDateMillis() {
		return submitDate;
	}

	public LocalDateTime getSubmitDate() {
		return LocalDateTime.ofInstant(Instant.ofEpochMilli(submitDate), ZoneId.systemDefault());
	}

	public void setSubmitDate(long submitDate) {
		this.submitDate = submitDate;
	}

	public long getStartDateMillis() {
		return startDate;
	}

	public LocalDateTime getStartDate() {
		return LocalDateTime.ofInstant(Instant.ofEpochMilli(startDate), ZoneId.systemDefault());
	}

	public void setStartDate(long startDate) {
		this.startDate = startDate;
	}

	public long getEndDateMillis() {
		return endDate;
	}

	public LocalDateTime getEndDate() {
		return LocalDateTime.ofInstant(Instant.ofEpochMilli(endDate), ZoneId.systemDefault());
	}

	public void setEndDate(long reviewedDate) {
		this.endDate = reviewedDate;
	}

	public long getNumViolations() {
		return getViolations().size();
	}

	public abstract List<V> getViolations();

	public void setStatus(ScanStatus status) {
		this.status = status;
	}

	public ScanStatus getStatus() {
		return this.status;
	}

	public void setError(String error) {
		if (error.length() > 255) {
			error = error.substring(0, 255);
		}
		this.errorMessage = error;
	}

	public String getError() {
		return this.errorMessage;
	}

}
