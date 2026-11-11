package com.tracelink.appsec.watchtower.core.alerting;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.lang3.StringUtils;

/**
 * Validates and masks Google Chat incoming-webhook URLs. The URL carries the space's key and
 * token, so it is treated as a credential: stored encrypted, never logged, and never shown back
 * in full. Only {@code https://chat.googleapis.com/v1/spaces/<space>/messages} is accepted, so a
 * channel can never be pointed at an internal or arbitrary host.
 *
 * @author Watchtower
 */
public final class GoogleChatWebhook {

	static final String HOST = "chat.googleapis.com";

	private static final Pattern PATH = Pattern.compile("/v1/spaces/([A-Za-z0-9_-]+)/messages");

	private static final String INVALID = "The URL must be a Google Chat incoming webhook"
			+ " (https://chat.googleapis.com/v1/spaces/.../messages).";

	private static final int SPACE_PREFIX_SHOWN = 4;

	private GoogleChatWebhook() {
	}

	/**
	 * @param raw a submitted URL
	 * @return the trimmed URL
	 * @throws IllegalArgumentException if it is not a Google Chat incoming webhook; the message
	 *                                  never echoes the URL
	 */
	public static String validate(String raw) {
		String url = StringUtils.trimToNull(raw);
		if (url == null) {
			throw new IllegalArgumentException("A Google Chat webhook URL is required.");
		}
		URI uri;
		try {
			uri = new URI(url);
		} catch (URISyntaxException e) {
			throw new IllegalArgumentException(INVALID);
		}
		boolean valid = "https".equals(uri.getScheme()) && HOST.equals(uri.getHost())
				&& uri.getRawUserInfo() == null && uri.getPort() == -1
				&& uri.getRawFragment() == null && uri.getRawPath() != null
				&& PATH.matcher(uri.getRawPath()).matches();
		if (!valid) {
			throw new IllegalArgumentException(INVALID);
		}
		return url;
	}

	/**
	 * @param url a stored webhook URL
	 * @return enough to recognise the space - never the key or token
	 */
	public static String mask(String url) {
		if (url == null) {
			return "";
		}
		try {
			URI uri = new URI(url);
			Matcher matcher = uri.getRawPath() == null ? null : PATH.matcher(uri.getRawPath());
			if (HOST.equals(uri.getHost()) && matcher != null && matcher.matches()) {
				String space = matcher.group(1);
				return "https://" + HOST + "/v1/spaces/"
						+ space.substring(0, Math.min(SPACE_PREFIX_SHOWN, space.length()))
						+ "…/messages?key=****";
			}
		} catch (URISyntaxException e) {
			// fall through to the fully masked form
		}
		return "****";
	}
}
