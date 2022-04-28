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
