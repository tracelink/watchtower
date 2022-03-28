package com.tracelink.appsec.watchtower.core.scan.image.ecr.entity;

import java.util.Collection;
import java.util.List;

import javax.persistence.CascadeType;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.OneToMany;
import javax.persistence.OrderBy;
import javax.persistence.Table;

import com.tracelink.appsec.watchtower.core.scan.AbstractScanContainer;

@Entity
@Table(name = "ecr_container")
public class EcrContainerEntity extends AbstractScanContainer<EcrScanEntity> {

	@Column(name = "api_label")
	private String apiLabel;

	@Column(name = "repo_name")
	private String repoName;

	@Column(name = "image_name")
	private String imageName;

	@Column(name = "tag_name")
	private String tagName;

	@OneToMany(fetch = FetchType.EAGER, mappedBy = "container", cascade = CascadeType.MERGE)
	@OrderBy(value = "end_date DESC")
	private List<EcrScanEntity> scans;

	@Override
	public Collection<EcrScanEntity> getScans() {
		return scans;
	}

}
