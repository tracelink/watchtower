package com.tracelink.appsec.watchtower.core.scan.code.scm.api;

import java.util.Locale;
import java.util.regex.Pattern;

import org.apache.commons.lang3.StringUtils;

/**
 * The one name Watchtower uses for a repository: its slug, as in Bitbucket's URLs and API paths
 * ({@code payments-api}). Bitbucket also gives a repository a display name ("Payments API"),
 * and a name typed into the manual scan form can be spelt either way; every key that tells
 * whether two requests are the same pull request (the SQS group, the work item, duplicate
 * checks, caches) compares names exactly, so all of them must see the slug.
 *
 * @author Watchtower
 */
public final class RepositorySlug {

	/** What a slug cannot hold, runs of which Bitbucket turns into one hyphen. */
	private static final Pattern NOT_SLUG = Pattern.compile("[^a-z0-9._-]+");

	private RepositorySlug() {
	}

	/**
	 * @param name a repository's slug or display name, in any case
	 * @return its slug: lower case, each run of other characters one hyphen, no hyphen at
	 *         either end; null for null. A slug is returned unchanged.
	 */
	public static String of(String name) {
		if (name == null) {
			return null;
		}
		String lower = name.trim().toLowerCase(Locale.ROOT);
		return StringUtils.strip(NOT_SLUG.matcher(lower).replaceAll("-"), "-");
	}
}
