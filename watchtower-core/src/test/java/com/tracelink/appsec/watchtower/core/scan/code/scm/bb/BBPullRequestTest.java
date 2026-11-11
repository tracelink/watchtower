package com.tracelink.appsec.watchtower.core.scan.code.scm.bb;

import com.tracelink.appsec.watchtower.core.scan.code.scm.api.bb.BBPullRequest;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.PullRequestState;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import org.json.JSONException;
import org.json.JSONObject;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class BBPullRequestTest {

	public static String author = "author";
	public static String sourceBranch = "sourceBranch";
	public static String sourceHash = "0123456789";
	public static String destinationBranch = "destinationBranch";
	public static String baseURL = "baseURL";
	public static String prBaseURL = "prBaseURL";
	public static String repo = "repo";
	public static int prId = 1;
	public static long updateTime = System.currentTimeMillis();

	@Test
	public void testBuildFromJSON() throws JSONException {
		BBPullRequest bbpr = new BBPullRequest("");
		bbpr.populateFromRequest(buildStandardJSONString());
		Assertions.assertEquals(author, bbpr.getAuthor());
		Assertions.assertEquals(sourceBranch, bbpr.getSourceBranch());
		Assertions.assertEquals(destinationBranch, bbpr.getDestinationBranch());
		Assertions.assertEquals(repo, bbpr.getRepoName());
		Assertions.assertEquals(prId, Integer.parseInt(bbpr.getPrId()));
		Assertions.assertEquals(PullRequestState.ACTIVE, bbpr.getState());
	}

	@Test
	public void theRepositoryIsNamedByItsSlugNotItsDisplayName() throws JSONException {
		// "Payments API" cannot go in a Bitbucket API path or an SQS group id
		JSONObject json = buildJSON();
		json.getJSONObject("repository").put("name", "Payments API")
				.put("full_name", "myworkspace/payments-api");
		BBPullRequest bbpr = new BBPullRequest("");
		bbpr.populateFromRequest(json.toString());
		Assertions.assertEquals("payments-api", bbpr.getRepoName());
	}

	@Test
	public void testMergedStateIsRecognised() throws JSONException {
		// Bitbucket reports a merged pull request as state MERGED. Mapping it onto
		// ACTIVE leaves the PR permanently unresolved, so the synchronizer re-fetches it
		// from Bitbucket every few hours forever.
		Assertions.assertEquals(PullRequestState.MERGED, stateFromBitbucket("MERGED"));
	}

	@Test
	public void testDeclinedStateIsRecognised() throws JSONException {
		Assertions.assertEquals(PullRequestState.DECLINED, stateFromBitbucket("DECLINED"));
	}

	@Test
	public void testOpenStateIsActive() throws JSONException {
		Assertions.assertEquals(PullRequestState.ACTIVE, stateFromBitbucket("OPEN"));
	}

	@Test
	public void testUnknownStateFallsBackToActive() throws JSONException {
		// A state Bitbucket adds in future must not break parsing.
		Assertions.assertEquals(PullRequestState.ACTIVE, stateFromBitbucket("SOMETHING_NEW"));
	}

	@Test
	public void testMergedAndDeclinedCountAsResolvedButActiveDoesNot() {
		Assertions.assertTrue(PullRequestState.MERGED.isResolved());
		Assertions.assertTrue(PullRequestState.DECLINED.isResolved());
		Assertions.assertFalse(PullRequestState.ACTIVE.isResolved());
	}

	@Test
	public void theFullCommitHashIsTakenFromTheCommitLinkWhenThePayloadAbbreviatesIt()
			throws JSONException {
		String full = "0123456789abcdef0123456789abcdef01234567";
		String shortHash = full.substring(0, 12);
		JSONObject pr = buildJSON().getJSONObject("pullrequest");
		pr.getJSONObject("source").put("commit", new JSONObject().put("hash", shortHash)
				.put("links", new JSONObject().put("self", new JSONObject().put("href",
						"https://api.bitbucket.org/2.0/repositories/ws/repo/commit/" + full))));
		BBPullRequest bbpr = new BBPullRequest("");

		bbpr.parsePullRequestJson(pr.toString());

		Assertions.assertEquals(full, bbpr.getCommitHash());
	}

	@Test
	public void anAbbreviatedHashWithoutAUsableLinkIsKeptAsIs() throws JSONException {
		JSONObject pr = buildJSON().getJSONObject("pullrequest");
		BBPullRequest bbpr = new BBPullRequest("");

		bbpr.parsePullRequestJson(pr.toString());

		Assertions.assertEquals(sourceHash, bbpr.getCommitHash());
	}

	@Test
	public void aFullHashFromThePayloadIsNotReplaced() throws JSONException {
		String full = "fedcba9876543210fedcba9876543210fedcba98";
		JSONObject pr = buildJSON().getJSONObject("pullrequest");
		pr.getJSONObject("source").put("commit", new JSONObject().put("hash", full));
		BBPullRequest bbpr = new BBPullRequest("");

		bbpr.parsePullRequestJson(pr.toString());

		Assertions.assertEquals(full, bbpr.getCommitHash());
	}

	private PullRequestState stateFromBitbucket(String state) throws JSONException {
		JSONObject json = buildJSON();
		json.getJSONObject("pullrequest").put("state", state);
		BBPullRequest bbpr = new BBPullRequest("");
		bbpr.populateFromRequest(json.toString());
		return bbpr.getState();
	}

	public static JSONObject buildJSON() throws JSONException {
		JSONObject authr = new JSONObject().put("display_name", author);
		JSONObject src = new JSONObject()
				.put("branch", new JSONObject().put("name", sourceBranch))
				.put("commit", new JSONObject().put("hash", sourceHash));

		JSONObject dst =
				new JSONObject().put("branch", new JSONObject().put("name", destinationBranch));
		JSONObject lnks = new JSONObject().put("self", new JSONObject().put("href", prBaseURL));

		JSONObject pr = new JSONObject();
		pr.put("author", authr);
		pr.put("source", src);
		pr.put("destination", dst);
		pr.put("links", lnks);
		pr.put("id", prId);
		pr.put("state", "OPEN");
		pr.put("updated_on",
				Instant.ofEpochMilli(updateTime).atOffset(ZoneOffset.UTC)
						.format(DateTimeFormatter.ISO_OFFSET_DATE_TIME));
		JSONObject rep = new JSONObject();
		rep.put("name", repo);
		rep.put("links", new JSONObject().put("self", new JSONObject().put("href", baseURL)));

		JSONObject json = new JSONObject();
		json.put("pullrequest", pr);
		json.put("repository", rep);

		return json;
	}

	public static String buildStandardJSONString() throws JSONException {
		return buildJSON().toString();
	}

}
