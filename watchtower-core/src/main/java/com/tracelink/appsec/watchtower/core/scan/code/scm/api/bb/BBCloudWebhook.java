package com.tracelink.appsec.watchtower.core.scan.code.scm.api.bb;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;

import kong.unirest.json.JSONArray;
import kong.unirest.json.JSONObject;

/** Safe read model. Never retain a remote secret, query string, fragment or URL credentials. */
public record BBCloudWebhook(String uuid, String urlHostPath, List<String> events,
		boolean active, boolean owned, boolean secretSet) {
	public BBCloudWebhook {
		events = List.copyOf(events);
	}

	static BBCloudWebhook from(JSONObject json, String callbackUrl) {
		String url = json.getString("url");
		List<String> events = new ArrayList<>();
		JSONArray values = json.optJSONArray("events");
		if (values != null) {
			for (int i = 0; i < values.length(); i++) {
				events.add(values.getString(i));
			}
		}
		return new BBCloudWebhook(json.getString("uuid"), displayUrl(url), events,
				json.optBoolean("active", false), callbackUrl.equals(url),
				json.optBoolean("secret_set", false));
	}

	private static String displayUrl(String url) {
		try {
			URI uri = URI.create(url);
			if (uri.getHost() == null || !("https".equals(uri.getScheme()) || "http".equals(uri.getScheme()))) {
				return "Invalid URL";
			}
			return uri.getHost() + (uri.getPort() < 0 ? "" : ":" + uri.getPort())
					+ (uri.getRawPath() == null ? "" : uri.getRawPath());
		} catch (IllegalArgumentException e) {
			return "Invalid URL";
		}
	}
}
