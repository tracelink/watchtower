package com.tracelink.appsec.watchtower.core.scan.repository;

import java.util.Collection;
import java.util.Date;
import java.util.List;

import jakarta.persistence.Column;
import jakarta.persistence.Convert;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.OneToOne;
import jakarta.persistence.Table;

import org.hibernate.annotations.DynamicUpdate;

import com.tracelink.appsec.watchtower.core.ruleset.RulesetEntity;
import com.tracelink.appsec.watchtower.core.scan.ScanType;
import com.tracelink.appsec.watchtower.core.scan.ScanType.ScanTypeConverter;

/**
 * Entity description for a repository. Holds information about a repository in a given SCM
 *
 * @author csmith
 */
/*
 * Dynamic update: a webhook's save writes only what it changed, so it cannot put back a stale
 * scanning_paused or last_repo_scan_id written meanwhile by a person or a scan.
 */
@Entity
@Table(name = "repositories")
@DynamicUpdate
public class RepositoryEntity {
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	@Column(name = "repo_entity_id")
	private long id;

	@jakarta.persistence.Version
	@Column(name = "configuration_version")
	private long configurationVersion;

	public long getConfigurationVersion() { return configurationVersion; }


	@Column(name = "scan_type")
	@Convert(converter = ScanTypeConverter.class)
	private ScanType scanType;

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

	@Column(name = "project_key")
	private String projectKey;

	@Column(name = "default_branch")
	private String defaultBranch;

	@Column(name = "last_commit_at")
	private Long lastCommitAt;

	@Column(name = "size_bytes")
	private Long sizeBytes;

	@Column(name = "primary_language")
	private String primaryLanguage;

	@Column(name = "scm_synced_at")
	private Long scmSyncedAt;

	@Column(name = "team")
	private String team;

	@Column(name = "owner_name")
	private String ownerName;

	/** Stored as ",a,b," so a label filter can match one label exactly with LIKE. */
	@Column(name = "labels")
	private String labels;

	@Column(name = "criticality")
	private int criticality = RepoCriticality.NORMAL.getLevel();

	@Column(name = "last_repo_scan_id")
	private Long lastRepoScanId;

	/** Set by a person only: webhooks and catalog syncs never change it. */
	@Column(name = "scanning_paused")
	private boolean scanningPaused;

	public long getId() {
		return id;
	}

	public ScanType getScanType() {
		return scanType;
	}

	public void setScanType(ScanType scanType) {
		this.scanType = scanType;
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

	/**
	 * @return true if a pull request of this repository has reached Watchtower; a repository
	 *         known only from a catalog sync has had none
	 */
	public boolean isPrActive() {
		return lastReviewedDate > 0;
	}

	public String getProjectKey() {
		return projectKey;
	}

	public void setProjectKey(String projectKey) {
		this.projectKey = projectKey;
	}

	public String getDefaultBranch() {
		return defaultBranch;
	}

	public void setDefaultBranch(String defaultBranch) {
		this.defaultBranch = defaultBranch;
	}

	/**
	 * @return epoch millis of the SCM's last update to the repository, 0 if unknown
	 */
	public long getLastCommitAt() {
		return lastCommitAt == null ? 0 : lastCommitAt;
	}

	public void setLastCommitAt(long lastCommitAt) {
		this.lastCommitAt = lastCommitAt;
	}

	public long getSizeBytes() {
		return sizeBytes == null ? 0 : sizeBytes;
	}

	public void setSizeBytes(long sizeBytes) {
		this.sizeBytes = sizeBytes;
	}

	public String getPrimaryLanguage() {
		return primaryLanguage;
	}

	public void setPrimaryLanguage(String primaryLanguage) {
		this.primaryLanguage = primaryLanguage;
	}

	public long getScmSyncedAt() {
		return scmSyncedAt == null ? 0 : scmSyncedAt;
	}

	public void setScmSyncedAt(long scmSyncedAt) {
		this.scmSyncedAt = scmSyncedAt;
	}

	public String getTeam() {
		return team;
	}

	public void setTeam(String team) {
		this.team = team;
	}

	public String getOwnerName() {
		return ownerName;
	}

	public void setOwnerName(String ownerName) {
		this.ownerName = ownerName;
	}

	/**
	 * @return the repository's labels, sorted; empty if it has none
	 */
	public List<String> getLabels() {
		return RepoLabels.parse(labels);
	}

	/**
	 * @param labels the labels to set, normalised by {@link RepoLabels#format(Collection)}
	 * @throws IllegalArgumentException if a label is not valid or there are too many
	 */
	public void setLabels(Collection<String> labels) {
		this.labels = RepoLabels.format(labels);
	}

	public int getCriticality() {
		return criticality;
	}

	public void setCriticality(int criticality) {
		this.criticality = RepoCriticality.of(criticality).getLevel();
	}

	public Long getLastRepoScanId() {
		return lastRepoScanId;
	}

	public void setLastRepoScanId(Long lastRepoScanId) {
		this.lastRepoScanId = lastRepoScanId;
	}

	public boolean isScanningPaused() {
		return scanningPaused;
	}

	public void setScanningPaused(boolean scanningPaused) {
		this.scanningPaused = scanningPaused;
	}
}
