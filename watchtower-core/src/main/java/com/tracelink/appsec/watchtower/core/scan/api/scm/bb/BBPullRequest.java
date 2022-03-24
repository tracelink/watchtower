package com.tracelink.appsec.watchtower.core.scan.api.scm.bb;

import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;

import com.jayway.jsonpath.DocumentContext;
import com.jayway.jsonpath.JsonPath;
import com.tracelink.appsec.watchtower.core.scan.code.pr.PullRequest;
import com.tracelink.appsec.watchtower.core.scan.code.pr.PullRequestState;

import kong.unirest.json.JSONObject;

/**
 * Added logic to create pull requests using bitbucket-specific knowledge.
 * <p>
 * Adds ability to create the pull request via JSON data sent by Bitbucket Cloud Server
 *
 * @author csmith
 */
public class BBPullRequest extends PullRequest {
	public BBPullRequest(String apiLabel) {
		super(apiLabel);
	}

	/**
	 * Fill this pull request with data from a Bitbucket webhook. The webhook contains pull request
	 * json and repository json
	 *
	 * @param json the webhook json string
	 */
	public void parseJsonFromWebhook(String json) {
		DocumentContext doc = JsonPath.parse(json);
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
			default:
				// handle open, updated, and anything else
				prState = PullRequestState.ACTIVE;
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
		setCommitHash(doc.read(sourceCommitHash));
		setPrId(Integer.toString(doc.read(prIdSearch)));
		setUpdateTime(
				LocalDateTime.parse(doc.read(updateSearch), DateTimeFormatter.ISO_OFFSET_DATE_TIME)
						.atOffset(ZoneOffset.UTC).toInstant().toEpochMilli());
		parsePRState(doc.read(stateSearch));
	}

	/**
	 * Add Repository information to this object using the Bitbucket API's Repository JSON
	 *
	 * @param repoJson the Bitbucket Repository json string
	 */
	public void parseRepositoryJson(String repoJson) {
		String repoSearch = "$.name";
		DocumentContext doc = JsonPath.parse(repoJson);
		setRepoName(doc.read(repoSearch));
	}

}
