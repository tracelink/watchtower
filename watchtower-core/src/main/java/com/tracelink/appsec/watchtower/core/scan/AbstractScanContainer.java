package com.tracelink.appsec.watchtower.core.scan;

import java.util.Collection;

import javax.persistence.Column;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.MappedSuperclass;

/**
 * The Abstract container is the superclass for the container database classes. It contains basic
 * information about the scan and holds a list of scans that are a part of the container
 * 
 * @param <S> a type describing the associated Scan
 * @author csmith
 *
 */
@MappedSuperclass
public abstract class AbstractScanContainer<S extends AbstractScanEntity<?, ?>> {
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	@Column(name = "container_id")
	private long id;

	@Column(name = "last_review_date")
	private long lastReviewedDate;

	public long getId() {
		return id;
	}

	public long getLastReviewedDate() {
		return lastReviewedDate;
	}

	public void setLastReviewedDate(long lastReviewedDate) {
		this.lastReviewedDate = lastReviewedDate;
	}

	public abstract Collection<S> getScans();
}
