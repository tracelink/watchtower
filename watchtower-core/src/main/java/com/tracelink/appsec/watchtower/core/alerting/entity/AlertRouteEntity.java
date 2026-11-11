package com.tracelink.appsec.watchtower.core.alerting.entity;

import com.tracelink.appsec.watchtower.core.alerting.AlertAggregation;
import com.tracelink.appsec.watchtower.core.rule.RulePriority;

import jakarta.persistence.Column;
import jakarta.persistence.Convert;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;

/**
 * Sends one alert type to one channel, optionally filtered. An alert type can have several
 * routes, e.g. to different spaces for different repositories.
 *
 * @author Watchtower
 */
@Entity
@Table(name = "alert_routes")
public class AlertRouteEntity {

	/** Once per finding per pull request, in practice. */
	public static final int DEFAULT_DEDUPE_WINDOW_HOURS = 720;

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	@Column(name = "route_id")
	private long id;

	@Column(name = "alert_type")
	private String alertType;

	@ManyToOne(fetch = FetchType.EAGER)
	@JoinColumn(name = "channel_id")
	private AlertChannelEntity channel;

	@Column(name = "enabled")
	private boolean enabled = true;

	/** Only items at least this severe alert; null for all. */
	@Column(name = "min_priority")
	@Convert(converter = RulePriority.RulePriorityNumberConverter.class)
	private RulePriority minPriority;

	/** Only this SCM integration; null for all. */
	@Column(name = "api_label_filter")
	private String apiLabelFilter;

	/** Comma-separated repository globs; null or empty for all. */
	@Column(name = "repo_include")
	private String repoInclude;

	/** Comma-separated repository globs to skip. */
	@Column(name = "repo_exclude")
	private String repoExclude;

	@Column(name = "aggregation")
	@Enumerated(EnumType.STRING)
	private AlertAggregation aggregation = AlertAggregation.PER_SCAN;

	@Column(name = "dedupe_window_hours")
	private int dedupeWindowHours = DEFAULT_DEDUPE_WINDOW_HOURS;

	@Column(name = "updated_by")
	private String updatedBy;

	@Column(name = "updated_at")
	private long updatedAt;

	/** Raised by every save, so a change prepared against an older route is refused. */
	@jakarta.persistence.Version
	@Column(name = "configuration_version")
	private long configurationVersion;

	public long getConfigurationVersion() {
		return configurationVersion;
	}

	public long getId() {
		return id;
	}

	public String getAlertType() {
		return alertType;
	}

	public void setAlertType(String alertType) {
		this.alertType = alertType;
	}

	public AlertChannelEntity getChannel() {
		return channel;
	}

	public void setChannel(AlertChannelEntity channel) {
		this.channel = channel;
	}

	public boolean isEnabled() {
		return enabled;
	}

	public void setEnabled(boolean enabled) {
		this.enabled = enabled;
	}

	public RulePriority getMinPriority() {
		return minPriority;
	}

	public void setMinPriority(RulePriority minPriority) {
		this.minPriority = minPriority;
	}

	public String getApiLabelFilter() {
		return apiLabelFilter;
	}

	public void setApiLabelFilter(String apiLabelFilter) {
		this.apiLabelFilter = apiLabelFilter;
	}

	public String getRepoInclude() {
		return repoInclude;
	}

	public void setRepoInclude(String repoInclude) {
		this.repoInclude = repoInclude;
	}

	public String getRepoExclude() {
		return repoExclude;
	}

	public void setRepoExclude(String repoExclude) {
		this.repoExclude = repoExclude;
	}

	public AlertAggregation getAggregation() {
		return aggregation;
	}

	public void setAggregation(AlertAggregation aggregation) {
		this.aggregation = aggregation;
	}

	public int getDedupeWindowHours() {
		return dedupeWindowHours;
	}

	public void setDedupeWindowHours(int dedupeWindowHours) {
		this.dedupeWindowHours = dedupeWindowHours;
	}

	public String getUpdatedBy() {
		return updatedBy;
	}

	public void setUpdatedBy(String updatedBy) {
		this.updatedBy = updatedBy;
	}

	public long getUpdatedAt() {
		return updatedAt;
	}

	public void setUpdatedAt(long updatedAt) {
		this.updatedAt = updatedAt;
	}
}
