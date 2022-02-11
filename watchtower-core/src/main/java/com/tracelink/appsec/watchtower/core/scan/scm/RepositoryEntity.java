package com.tracelink.appsec.watchtower.core.scan.scm;

import java.util.Date;

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

/**
 * Entity description for a repository. Holds information about a repository in a given SCM
 *
 * @author csmith
 */
@Entity
@Table(name = "repositories")
public class RepositoryEntity {
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	@Column(name = "repo_entity_id")
	private long id;

	@Column(name = "last_review_date")
	private long lastReviewedDate;

	@Column(name = "api_label")
	private String apiLabel;

	@Column(name = "repo_name")
	private String repoName;

	@Column(name = "enabled")
	private boolean enabled;

	@OneToOne(fetch = FetchType.EAGER)
	@JoinColumn(name = "ruleset_id")
	private RulesetEntity ruleset;

	public long getId() {
		return id;
	}

	public long getLastReviewedDate() {
		return lastReviewedDate;
	}

	public Date getLastReviewedDateAsDate() {
		return new Date(lastReviewedDate);
	}

	public void setLastReviewedDate(long lastReviewedDate) {
		this.lastReviewedDate = lastReviewedDate;
	}

	public String getApiLabel() {
		return apiLabel;
	}

	public void setApiLabel(String apiLabel) {
		this.apiLabel = apiLabel;
	}

	public String getRepoName() {
		return repoName;
	}

	public void setRepoName(String repoName) {
		this.repoName = repoName;
	}

	public RulesetEntity getRuleset() {
		return ruleset;
	}

	public void setRuleset(RulesetEntity ruleset) {
		this.ruleset = ruleset;
	}

	public void setEnabled(boolean enabled) {
		this.enabled = enabled;
	}

	public boolean isEnabled() {
		return enabled;
	}
}
