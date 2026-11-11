package com.tracelink.appsec.watchtower.core.scan.code.scm.api.bb;

import java.nio.charset.StandardCharsets;
import java.time.OffsetDateTime;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Consumer;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.tracelink.appsec.watchtower.core.scan.code.scm.api.FileFetch;
import com.tracelink.appsec.watchtower.core.scan.code.scm.api.ScmBranch;
import com.tracelink.appsec.watchtower.core.scan.code.scm.api.ScmRepository;

import kong.unirest.GetRequest;
import kong.unirest.HttpResponse;
import kong.unirest.JsonNode;
import kong.unirest.Unirest;
import kong.unirest.UnirestException;
import kong.unirest.json.JSONArray;
import kong.unirest.json.JSONObject;

/**
 * Bitbucket Cloud calls for whole repositories rather than pull requests: listing the
 * workspace's repositories, reading branches, and reading a single file at a commit for
 * display. Every listing asks for only the fields Watchtower keeps (Bitbucket partial
 * responses), which keeps a workspace-wide listing small.
 *
 * @author Watchtower
 */
class BBCloudRepositories {

	private static final Logger LOG = LoggerFactory.getLogger(BBCloudRepositories.class);

	private static final int PAGE_LENGTH = 100;

	/** 200 pages of 100; a workspace larger than this is reported as incompletely listed. */
	private static final int MAX_REPOSITORY_PAGES = 200;

	private static final String REPOSITORY_FIELDS = "next,values.slug,values.project.key,"
			+ "values.mainbranch.name,values.updated_on,values.size,values.language";

	private static final String SINGLE_REPOSITORY_FIELDS =
			"slug,project.key,mainbranch.name,updated_on,size,language";

	private static final String BRANCH_FIELDS =
			"next,values.name,values.target.hash,values.target.date";

	/** A file larger than this is not fetched for display. */
	static final int MAX_DISPLAY_FILE_BYTES = 2 * 1024 * 1024;

	private final BBCloudIntegrationEntity apiEntity;

	BBCloudRepositories(BBCloudIntegrationEntity apiEntity) {
		this.apiEntity = apiEntity;
	}

	boolean list(Consumer<List<ScmRepository>> pageConsumer) {
		String url = apiEntity.makeApiWorkspaceUrl();
		Map<String, Object> firstPage =
				Map.of("pagelen", PAGE_LENGTH, "fields", REPOSITORY_FIELDS);
		try {
			for (int page = 0; page < MAX_REPOSITORY_PAGES; page++) {
				String pageUrl = url;
				// "next" already carries pagelen and fields
				Map<String, Object> params = page == 0 ? firstPage : null;
				HttpResponse<JsonNode> response =
						BBCloudApi.withRetry(() -> get(pageUrl).queryString(params).asJson());
				if (response.getStatus() != 200) {
					LOG.error("Bad response: {} while listing repositories of workspace {}",
							response.getStatus(), apiEntity.getWorkspace());
					return false;
				}
				JSONObject body = response.getBody().getObject();
				pageConsumer.accept(parseRepositories(body.optJSONArray("values")));
				url = body.optString("next", null);
				if (url == null) {
					return true;
				}
			}
			LOG.error("Workspace {} has more than {} pages of repositories; listing stopped",
					apiEntity.getWorkspace(), MAX_REPOSITORY_PAGES);
			return false;
		} catch (UnirestException e) {
			LOG.error("Exception while listing repositories of workspace "
					+ apiEntity.getWorkspace(), e);
			return false;
		}
	}

	Optional<ScmRepository> getRepository(String repoName) {
		try {
			HttpResponse<JsonNode> response = BBCloudApi.withRetry(
					() -> get(apiEntity.makeApiRepoUrl(repoName))
							.queryString("fields", SINGLE_REPOSITORY_FIELDS).asJson());
			if (response.getStatus() == 404) {
				return Optional.empty();
			}
			if (response.getStatus() != 200) {
				LOG.error("Bad response: {} while reading repository {}", response.getStatus(),
						repoName);
				return Optional.empty();
			}
			return parseRepositories(new JSONArray().put(response.getBody().getObject()))
					.stream().findFirst();
		} catch (UnirestException e) {
			LOG.error("Exception while reading repository " + repoName, e);
			return Optional.empty();
		}
	}

	List<ScmBranch> listBranches(String repoName, String nameFilter, int limit) {
		if (limit <= 0) {
			return Collections.emptyList();
		}
		String query = StringUtils.isBlank(nameFilter) ? null
				: "name ~ \"" + escapeQueryValue(nameFilter) + "\"";
		List<ScmBranch> branches = new ArrayList<>();
		String url = branchesUrl(repoName);
		Map<String, Object> params = branchParams(query, Math.min(limit, PAGE_LENGTH));
		try {
			while (url != null && branches.size() < limit) {
				String pageUrl = url;
				Map<String, Object> pageParams = params;
				HttpResponse<JsonNode> response =
						BBCloudApi.withRetry(() -> get(pageUrl).queryString(pageParams).asJson());
				if (response.getStatus() != 200) {
					LOG.error("Bad response: {} while listing branches of {}",
							response.getStatus(), repoName);
					return Collections.emptyList();
				}
				JSONObject body = response.getBody().getObject();
				branches.addAll(parseBranches(body.optJSONArray("values")));
				url = body.optString("next", null);
				params = null;
			}
		} catch (UnirestException e) {
			LOG.error("Exception while listing branches of " + repoName, e);
			return Collections.emptyList();
		}
		return List.copyOf(branches.subList(0, Math.min(limit, branches.size())));
	}

	Optional<ScmBranch> getBranch(String repoName, String branchName) {
		if (StringUtils.isBlank(branchName)) {
			return Optional.empty();
		}
		// An exact-match query rather than refs/branches/{name}: branch names contain
		// slashes (release/1.0), which a query parameter carries without path-encoding rules
		String query = "name = \"" + escapeQueryValue(branchName) + "\"";
		try {
			HttpResponse<JsonNode> response = BBCloudApi.withRetry(
					() -> get(branchesUrl(repoName)).queryString(branchParams(query, 1))
							.asJson());
			if (response.getStatus() != 200) {
				LOG.error("Bad response: {} while reading branch {} of {}",
						response.getStatus(), branchName, repoName);
				return Optional.empty();
			}
			return parseBranches(response.getBody().getObject().optJSONArray("values"))
					.stream().filter(b -> branchName.equals(b.name())).findFirst();
		} catch (UnirestException e) {
			LOG.error("Exception while reading branch " + branchName + " of " + repoName, e);
			return Optional.empty();
		}
	}

	String getFileContent(String repoName, String commitHash, String filePath) {
		return fetchFile(repoName, commitHash, filePath).content();
	}

	/** One file at one commit, with the reason in words when Bitbucket would not give it. */
	FileFetch fetchFile(String repoName, String commitHash, String filePath) {
		String url = apiEntity.makeSourceFileUrl(repoName, commitHash, filePath);
		try {
			HttpResponse<byte[]> response = BBCloudApi.withRetry(() -> get(url).asBytes());
			int status = response.getStatus();
			if (status != 200) {
				LOG.debug("Response {} while reading {} at {} of {}", status, filePath, commitHash,
						repoName);
				return FileFetch.unavailable(reasonFor(status));
			}
			byte[] content = response.getBody();
			if (content == null) {
				return FileFetch.unavailable("Bitbucket returned an empty answer for the file.");
			}
			if (content.length > MAX_DISPLAY_FILE_BYTES) {
				return FileFetch.unavailable("The file is larger than "
						+ MAX_DISPLAY_FILE_BYTES / (1024 * 1024) + " MB, so it is not shown.");
			}
			return FileFetch.found(new String(content, StandardCharsets.UTF_8));
		} catch (UnirestException e) {
			LOG.warn("Exception while reading " + filePath + " of " + repoName, e);
			return FileFetch.unavailable(e.getMessage() != null && e.getMessage().contains("RateLimiter")
					? "Bitbucket was limiting Watchtower's requests; try again in a few minutes."
					: "Watchtower could not reach Bitbucket.");
		}
	}

	static String reasonFor(int status) {
		return switch (status) {
			case 404 -> "The file is not at the scanned commit: it was deleted or renamed, or the"
					+ " commit is no longer in Bitbucket.";
			case 401, 403 -> "Watchtower's Bitbucket access cannot read this repository.";
			case 429 -> "Bitbucket was limiting Watchtower's requests; try again in a few minutes.";
			default -> "Bitbucket answered with an error (HTTP " + status + ").";
		};
	}

	static List<ScmRepository> parseRepositories(JSONArray values) {
		if (values == null) {
			return Collections.emptyList();
		}
		List<ScmRepository> repositories = new ArrayList<>(values.length());
		for (int i = 0; i < values.length(); i++) {
			JSONObject value = values.getJSONObject(i);
			String slug = StringUtils.trimToNull(value.optString("slug", null));
			if (slug == null) {
				continue;
			}
			JSONObject project = value.optJSONObject("project");
			JSONObject mainBranch = value.optJSONObject("mainbranch");
			repositories.add(new ScmRepository(slug,
					project == null ? null : StringUtils.trimToNull(project.optString("key")),
					mainBranch == null ? null
							: StringUtils.trimToNull(mainBranch.optString("name")),
					parseMillis(value.optString("updated_on", null)),
					Math.max(0, value.optLong("size", 0)),
					StringUtils.trimToNull(value.optString("language", null))));
		}
		return repositories;
	}

	static List<ScmBranch> parseBranches(JSONArray values) {
		if (values == null) {
			return Collections.emptyList();
		}
		List<ScmBranch> branches = new ArrayList<>(values.length());
		for (int i = 0; i < values.length(); i++) {
			JSONObject value = values.getJSONObject(i);
			JSONObject target = value.optJSONObject("target");
			String name = StringUtils.trimToNull(value.optString("name", null));
			String hash = target == null ? null : StringUtils.trimToNull(target.optString("hash"));
			if (name == null || hash == null) {
				continue;
			}
			branches.add(new ScmBranch(name, hash, parseMillis(target.optString("date", null))));
		}
		return branches;
	}

	static long parseMillis(String isoDate) {
		if (StringUtils.isBlank(isoDate)) {
			return 0;
		}
		try {
			return OffsetDateTime.parse(isoDate).toInstant().toEpochMilli();
		} catch (DateTimeParseException e) {
			return 0;
		}
	}

	/**
	 * Escapes a value for a double-quoted Bitbucket query string, so a backslash or quote in
	 * a branch name cannot end the string early and change the query.
	 */
	static String escapeQueryValue(String value) {
		return value.replace("\\", "\\\\").replace("\"", "\\\"");
	}

	private static Map<String, Object> branchParams(String query, int pageLength) {
		Map<String, Object> params = new HashMap<>();
		params.put("pagelen", pageLength);
		params.put("fields", BRANCH_FIELDS);
		params.put("sort", "-target.date");
		if (query != null) {
			params.put("q", query);
		}
		return params;
	}

	private String branchesUrl(String repoName) {
		return apiEntity.makeApiRepoUrl(repoName) + "/refs/branches";
	}

	private GetRequest get(String url) {
		return Unirest.get(url).basicAuth(apiEntity.getUser(), apiEntity.getAuth())
				.header("accept", "application/json");
	}
}
