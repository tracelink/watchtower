package com.tracelink.appsec.watchtower.core.scan.code.scm.api.bb;

import com.jayway.jsonpath.DocumentContext;
import com.jayway.jsonpath.JsonPath;
import com.jayway.jsonpath.PathNotFoundException;
import com.tracelink.appsec.watchtower.core.scan.code.scm.api.RepositorySlug;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.PullRequest;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.PullRequestState;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.regex.Pattern;
import kong.unirest.json.JSONObject;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Added logic to create pull requests using bitbucket-specific knowledge.
 * <p>
 * Adds ability to create the pull request via JSON data sent by Bitbucket Cloud Server
 *
 * @author csmith
 */
public class BBPullRequest extends PullRequest {

	private static final Logger LOG = LoggerFactory.getLogger(BBPullRequest.class);

	public BBPullRequest(String apiLabel) {
		super(apiLabel);
	}

	/**
	 * Fill this pull request with data from a Bitbucket webhook. The webhook contains pull request
	 * json and repository json
	 *
	 * @param requestBody the webhook json string
	 */
	public void populateFromRequest(String requestBody) {
		DocumentContext doc = JsonPath.parse(requestBody);
		String pullRequestJson = JSONObject.valueToString(doc.read("$.pullrequest"));
		String repoJson = JSONObject.valueToString(doc.read("$.repository"));

		parsePullRequestJson(pullRequestJson);
		parseRepositoryJson(repoJson);
	}

	private void parsePRState(String state) {
		PullRequestState prState;

		switch (state.toLowerCase()) {
			case "declined":
				prState = PullRequestState.DECLINED;
				break;
			case "merged":
				prState = PullRequestState.MERGED;
				break;
			default:
				// handle open, updated, and anything else
				prState = PullRequestState.ACTIVE;
				if (!"open".equalsIgnoreCase(state)) {
					// Falling back to ACTIVE keeps an unfamiliar state from breaking the
					// scan, but a state we do not recognise means the Pull Request may
					// never be resolved, so make it visible.
					LOG.debug("Unrecognised Bitbucket pull request state '" + state
							+ "', treating as ACTIVE");
				}
				break;
		}
		setState(prState);
	}

	/**
	 * Add Pull Request information to this object using the Bitbucket API's Pull Request JSON
	 *
	 * @param prJson the Bitbucket PR json string
	 */
	public void parsePullRequestJson(String prJson) {
		String authorSearch = "$.author.display_name";
		String sourceBranchSearch = "$.source.branch.name";
		String sourceCommitHash = "$.source.commit.hash";
		String destinationBranchSearch = "$.destination.branch.name";
		String prIdSearch = "$.id";
		String updateSearch = "$.updated_on";
		String stateSearch = "$.state";

		DocumentContext doc = JsonPath.parse(prJson);
		setAuthor(doc.read(authorSearch));
		setSourceBranch(doc.read(sourceBranchSearch));
		setDestinationBranch(doc.read(destinationBranchSearch));
		setCommitHash(fullHash(doc, "$.source.commit", doc.read(sourceCommitHash)));
		setBaseCommitHash(fullHash(doc, "$.destination.commit",
				readOrNull(doc, "$.destination.commit.hash")));
		setPrId(Integer.toString(doc.read(prIdSearch)));
		setUpdateTime(
				LocalDateTime.parse(doc.read(updateSearch), DateTimeFormatter.ISO_OFFSET_DATE_TIME)
						.atOffset(ZoneOffset.UTC).toInstant().toEpochMilli());
		parsePRState(doc.read(stateSearch));
	}

	/**
	 * Add Repository information to this object using the Bitbucket API's Repository JSON. The
	 * repository is named by its slug, from {@code full_name} ("workspace/slug"): what
	 * Bitbucket's API paths take and the catalog sync lists. Its display name ({@code name},
	 * e.g. "Payments API") can hold spaces, which no API path or SQS group id accepts; it is the
	 * fallback only for a payload without a {@code full_name}.
	 *
	 * @param repoJson the Bitbucket Repository json string
	 */
	public void parseRepositoryJson(String repoJson) {
		DocumentContext doc = JsonPath.parse(repoJson);
		String slug = StringUtils.substringAfter(readOrNull(doc, "$.full_name"), "/");
		setRepoName(RepositorySlug.of(StringUtils.isBlank(slug) ? doc.read("$.name") : slug));
	}

	private static final Pattern FULL_HASH = Pattern.compile("[a-f0-9]{40}");

	/**
	 * Bitbucket's pull request payload abbreviates commit hashes to 12 characters, while source
	 * reads, the AI assessment and the report's pinned commit want the full one. The commit's
	 * own link ends in it.
	 */
	private static String fullHash(DocumentContext doc, String commitPath, String hash) {
		if (hash != null && FULL_HASH.matcher(hash).matches()) {
			return hash;
		}
		String href = readOrNull(doc, commitPath + ".links.self.href");
		if (href != null) {
			String last = StringUtils.substringAfterLast(StringUtils.removeEnd(href, "/"), "/");
			if (FULL_HASH.matcher(last).matches() && (hash == null || last.startsWith(hash))) {
				return last;
			}
		}
		return hash;
	}

	private static String readOrNull(DocumentContext doc, String path) {
		try {
			Object value = doc.read(path);
			return value == null ? null : value.toString();
		} catch (PathNotFoundException e) {
			return null;
		}
	}

}
