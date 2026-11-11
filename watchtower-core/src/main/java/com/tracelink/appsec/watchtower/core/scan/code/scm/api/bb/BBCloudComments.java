package com.tracelink.appsec.watchtower.core.scan.code.scm.api.bb;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.PullRequest;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.PullRequestComment;

import kong.unirest.HttpRequest;
import kong.unirest.HttpResponse;
import kong.unirest.JsonNode;
import kong.unirest.Unirest;
import kong.unirest.UnirestException;
import kong.unirest.json.JSONArray;
import kong.unirest.json.JSONObject;

/**
 * Bitbucket Cloud pull request comment calls beyond the summary comment: listing, inline
 * comments, editing and deleting (§4.14). {@link BBCloudApi} decides whether commenting is
 * enabled at all and delegates here.
 *
 * @author Watchtower
 */
class BBCloudComments {

	private static final Logger LOG = LoggerFactory.getLogger(BBCloudComments.class);

	private static final String COMMENTS_PATH = "comments";

	private static final int PAGE_LENGTH = 100;

	/** A PR with more comments than this many pages is listed only in part. */
	private static final int MAX_PAGES = 20;

	private final BBCloudIntegrationEntity apiEntity;

	BBCloudComments(BBCloudIntegrationEntity apiEntity) {
		this.apiEntity = apiEntity;
	}

	/**
	 * @return the comments that are not deleted, or null if they could not be read
	 */
	List<PullRequestComment> list(PullRequest pr) {
		List<PullRequestComment> comments = new ArrayList<>();
		String url = commentsUrl(pr);
		Map<String, Object> firstPage = Map.of("pagelen", PAGE_LENGTH);
		try {
			for (int page = 0; url != null && page < MAX_PAGES; page++) {
				String pageUrl = url;
				Map<String, Object> params = page == 0 ? firstPage : null;
				HttpResponse<JsonNode> response = withRetry(() -> authorize(Unirest.get(pageUrl))
						.queryString(params).asJson());
				if (response.getStatus() != 200) {
					LOG.error("Bad response: {} while listing comments of PR {}",
							response.getStatus(), pr.getPRString());
					return null;
				}
				JSONObject body = response.getBody().getObject();
				addComments(body.getJSONArray("values"), comments);
				url = body.optString("next", null);
			}
			return comments;
		} catch (UnirestException e) {
			LOG.error("Exception while listing comments of PR " + pr.getPRString(), e);
			return null;
		}
	}

	boolean postInline(PullRequest pr, String path, int line, String text) {
		JSONObject body = content(text)
				.put("inline", new JSONObject().put("path", path).put("to", line));
		return send(pr, "commenting inline on", 201,
				() -> authorize(Unirest.post(commentsUrl(pr)))
						.header("content-type", "application/json").body(body).asString());
	}

	boolean reply(PullRequest pr, long parentId, String text) {
		JSONObject body = content(text).put("parent", new JSONObject().put("id", parentId));
		return send(pr, "replying to a comment of", 201,
				() -> authorize(Unirest.post(commentsUrl(pr)))
						.header("content-type", "application/json").body(body).asString());
	}

	boolean update(PullRequest pr, long commentId, String text) {
		JSONObject body = content(text);
		return send(pr, "editing a comment of", 200,
				() -> authorize(Unirest.put(commentUrl(pr, commentId)))
						.header("content-type", "application/json").body(body).asString());
	}

	boolean delete(PullRequest pr, long commentId) {
		return send(pr, "deleting a comment of", 204,
				() -> authorize(Unirest.delete(commentUrl(pr, commentId))).asString());
	}

	private boolean send(PullRequest pr, String action, int expected,
			Supplier<HttpResponse<String>> call) {
		try {
			HttpResponse<String> response = withRetry(call);
			if (response.getStatus() != expected) {
				LOG.warn("Bad response: {} while {} PR {}", response.getStatus(), action,
						pr.getPRString());
				return false;
			}
			return true;
		} catch (UnirestException e) {
			LOG.error("Exception while " + action + " PR " + pr.getPRString(), e);
			return false;
		}
	}

	private static <T> HttpResponse<T> withRetry(Supplier<HttpResponse<T>> call) {
		return BBCloudApi.withRetry(call);
	}

	private static void addComments(JSONArray values, List<PullRequestComment> comments) {
		for (int i = 0; i < values.length(); i++) {
			JSONObject value = values.getJSONObject(i);
			if (value.optBoolean("deleted", false)) {
				continue;
			}
			JSONObject inline = value.optJSONObject("inline");
			String path = inline == null ? null : StringUtils.trimToNull(inline.optString("path"));
			Integer line = inline == null || inline.isNull("to") ? null : inline.optInt("to");
			String raw = value.optJSONObject("content") == null ? ""
					: value.getJSONObject("content").optString("raw", "");
			comments.add(new PullRequestComment(value.getLong("id"), raw, path, line));
		}
	}

	private static JSONObject content(String text) {
		return new JSONObject().put("content", new JSONObject().put("raw", text));
	}

	private <R extends HttpRequest<?>> R authorize(R request) {
		request.basicAuth(apiEntity.getUser(), apiEntity.getAuth())
				.header("accept", "application/json");
		return request;
	}

	private String commentsUrl(PullRequest pr) {
		return apiEntity.makeApiPRUrl(pr.getRepoName(), pr.getPrId()) + "/" + COMMENTS_PATH;
	}

	private String commentUrl(PullRequest pr, long commentId) {
		return commentsUrl(pr) + "/" + commentId;
	}
}
