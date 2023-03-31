package com.tracelink.appsec.watchtower.core.scan.code.scm.pr.entity;

import java.util.List;

import javax.persistence.*;

import com.tracelink.appsec.watchtower.core.scan.AbstractScanEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.PullRequestMCRStatus;

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

	@Column(name = "mcr_status")
	private PullRequestMCRStatus mcrStatus;

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

	public PullRequestMCRStatus getMcrStatus() {
		return mcrStatus;
	}

	public void setMcrStatus(PullRequestMCRStatus mcrStatus) { this.mcrStatus = mcrStatus;	}

}
