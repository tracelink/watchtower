package com.tracelink.appsec.watchtower.core.alerting;

import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.tracelink.appsec.watchtower.core.alerting.entity.AlertLogEntity;

/**
 * One delivery in the alert history (UAT #35): when it was raised and sent, which repository and
 * Watchtower page it was about, where it went, and its outcome. The repository and link are read
 * back from the saved message, which is exactly what was posted to the channel.
 *
 * @param failedAttempts sends that failed; 0 with status Sent means the first send succeeded
 */
public record AlertHistoryRow(long id, long createdAt, Long sentAt, String type, String repository, String channel,
		String status, int failedAttempts, String lastError, String message, String sourceLink) {

	private static final Pattern REPOSITORY = Pattern.compile("(?m)^Repository: (.+)$");
	private static final Pattern LINK = Pattern.compile("<((?:https?://|/)[^|>\\s]+)\\|Open in Watchtower>");

	public static AlertHistoryRow from(AlertLogEntity log, Map<Long, String> channelNames) {
		String payload = log.getPayload() == null ? "" : log.getPayload();
		Matcher repository = REPOSITORY.matcher(payload);
		Matcher link = LINK.matcher(payload);
		return new AlertHistoryRow(log.getId(), log.getCreatedAt(), log.getSentAt(), label(log.getAlertType()),
				repository.find() ? repository.group(1).strip() : null,
				channelNames.getOrDefault(log.getChannelId(), "Deleted channel"), label(String.valueOf(log.getStatus())),
				log.getAttempts(), log.getLastError(), payload, link.find() ? link.group(1) : null);
	}

	private static String label(String key) {
		String text = key == null ? "" : key.replace('_', ' ').toLowerCase(java.util.Locale.ROOT).replaceAll("\\bpr\\b", "PR");
		return text.isEmpty() ? text : Character.toUpperCase(text.charAt(0)) + text.substring(1);
	}
}
