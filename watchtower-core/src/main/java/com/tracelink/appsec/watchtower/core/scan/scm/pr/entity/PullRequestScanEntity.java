package com.tracelink.appsec.watchtower.core.scan.scm.pr.entity;

import java.util.List;

import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
import javax.persistence.OneToMany;
import javax.persistence.Table;

import com.tracelink.appsec.watchtower.core.scan.AbstractScanEntity;

/**
 * Scan Entity class for Pull Requests with join to {@linkplain PullRequestContainerEntity} and
 * reverse join to {@linkplain PullRequestViolationEntity}
 * 
 * @author csmith
 *
 */
@Entity
@Table(name = "pull_request_scans")
public class PullRequestScanEntity
		extends AbstractScanEntity<PullRequestContainerEntity, PullRequestViolationEntity> {

	@ManyToOne(fetch = FetchType.EAGER)
	@JoinColumn(name = "container_id", nullable = false)
	private PullRequestContainerEntity container;

	@OneToMany(fetch = FetchType.EAGER, mappedBy = "scan")
	private List<PullRequestViolationEntity> violations;

	@Override
	public PullRequestContainerEntity getContainer() {
		return container;
	}

	@Override
	public void setContainer(PullRequestContainerEntity container) {
		this.container = container;
	}

	@Override
	public List<PullRequestViolationEntity> getViolations() {
		return violations;
	}

}
