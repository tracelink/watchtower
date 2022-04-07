package com.tracelink.appsec.watchtower.core.scan.image.registry;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.OneToOne;
import javax.persistence.Table;

import com.tracelink.appsec.watchtower.core.ruleset.RulesetEntity;

@Entity
@Table(name = "registry_image")
public class RegistryImageEntity {
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	@Column(name = "registry_image_entity_id")
	private long registryImageId;

	@Column(name = "image_name")
	private String registryImageName;

	@Column(name = "api_label")
	private String apiLabel;

	@Column(name = "last_review_date")
	private long lastReviewedDate;

	@Column(name = "enabled")
	private boolean enabled;

	@OneToOne(fetch = FetchType.EAGER)
	@JoinColumn(name = "ruleset_id")
	private RulesetEntity ruleset;

	public long getRegistryImageId() {
		return registryImageId;
	}

	public void setRegistryImageId(long registryImageId) {
		this.registryImageId = registryImageId;
	}

	public String getRegistryImageName() {
		return registryImageName;
	}

	public void setRegistryImageName(String registryImageName) {
		this.registryImageName = registryImageName;
	}

	public String getApiLabel() {
		return apiLabel;
	}

	public void setApiLabel(String apiLabel) {
		this.apiLabel = apiLabel;
	}

	public long getLastReviewedDate() {
		return lastReviewedDate;
	}

	public void setLastReviewedDate(long lastReviewedDate) {
		this.lastReviewedDate = lastReviewedDate;
	}

	public boolean isEnabled() {
		return enabled;
	}

	public void setEnabled(boolean enabled) {
		this.enabled = enabled;
	}

	public RulesetEntity getRuleset() {
		return ruleset;
	}

	public void setRuleset(RulesetEntity ruleset) {
		this.ruleset = ruleset;
	}

}
