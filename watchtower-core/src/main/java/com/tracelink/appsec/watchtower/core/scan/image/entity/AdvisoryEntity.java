package com.tracelink.appsec.watchtower.core.scan.image.entity;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.Table;

@Entity
@Table(name = "advisories")
public class AdvisoryEntity {
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	@Column(name = "advisory_id")
	private long id;

	@Column(name = "finding_name")
	private String findingName;

	@Column(name = "package_name")
	private String packageName;

	@Column(name = "score")
	private String score;

	@Column(name = "vector")
	private String vector;

	@Column(name = "description")
	private String description;

	@Column(name = "uri")
	private String uri;

	public String getFindingName() {
		return findingName;
	}

	public void setFindingName(String findingName) {
		this.findingName = findingName;
	}

	public String getPackageName() {
		return packageName;
	}

	public void setPackageName(String packageName) {
		this.packageName = packageName;
	}

	public String getScore() {
		return score;
	}

	public void setScore(String score) {
		this.score = score;
	}

	public String getVector() {
		return vector;
	}

	public void setVector(String vector) {
		this.vector = vector;
	}

	public String getDescription() {
		return description;
	}

	public void setDescription(String description) {
		this.description = description;
	}

	public String getUri() {
		return uri;
	}

	public void setUri(String uri) {
		this.uri = uri;
	}
}
