package com.tracelink.appsec.watchtower.core.scan.code.scm.api.bb;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;
import java.util.function.Supplier;
import java.util.stream.Stream;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.jayway.jsonpath.JsonPath;
import com.tracelink.appsec.watchtower.core.exception.PullRequestNotFoundException;
import com.tracelink.appsec.watchtower.core.exception.RateLimitedException;
import com.tracelink.appsec.watchtower.core.exception.ScanRejectedException;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.ApiIntegrationException;
import com.tracelink.appsec.watchtower.core.scan.code.scm.api.IScmApi;
import com.tracelink.appsec.watchtower.core.scan.code.scm.api.ScmBranch;
import com.tracelink.appsec.watchtower.core.scan.code.scm.api.ScmRepository;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.PullRequest;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.PullRequestComment;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.data.DiffFile;

import kong.unirest.GetRequest;
import kong.unirest.Headers;
import kong.unirest.HttpRequestWithBody;
import kong.unirest.HttpResponse;
import kong.unirest.JsonNode;
import kong.unirest.Unirest;
import kong.unirest.UnirestException;
import kong.unirest.json.JSONArray;
import kong.unirest.json.JSONObject;
import com.tracelink.appsec.watchtower.core.scan.code.SecureZipUtils;
import com.tracelink.appsec.watchtower.core.scan.code.scm.api.SourceDownloadLimits;

/**
 * An implementation of the {@linkplain IScmApi} for Bitbucket Cloud
 *
 * @author csmith
 */
public class BBCloudApi implements IScmApi {

	private static final Logger LOG = LoggerFactory.getLogger(BBCloudApi.class);

	/**
	 * Number of times a source zip download is attempted before giving up.
	 */
	private static final int MAX_DOWNLOAD_ATTEMPTS = 5;

	/**
	 * Error bodies are logged at DEBUG only, truncated: Bitbucket can echo request content (file
	 * text, comments) back, and log masking only catches known credential formats.
	 */
	private static final int MAX_LOGGED_BODY = 500;

	private static final String APPROVE_PATH = "approve";
	private static final String REQUEST_CHANGES_PATH = "request-changes";

	/**
	 * Number of random bytes in a generated webhook secret (256 bits).
	 */
	private static final int WEBHOOK_SECRET_BYTES = 32;

	/**
	 * Bitbucket events the registered webhook should deliver. Includes the resolve events
	 * from item 5.1 so a merged/declined PR resolves at the webhook rather than waiting for
	 * the next synchronizer pass, and new comments for "/watchtower bypass <reason>" requests
	 * (§4.18). Existing integrations pick up a change here when re-registered.
	 */
	private static final List<String> WEBHOOK_EVENTS = List.of("pullrequest:created",
			"pullrequest:updated", "pullrequest:fulfilled", "pullrequest:rejected",
			"pullrequest:comment_created");

	private static final SecureRandom SECURE_RANDOM = new SecureRandom();

	private static final int MAX_RATE_LIMIT_RETRIES = 5;

	private final BBCloudIntegrationEntity apiEntity;

	private final BBCloudComments comments;

	private final BBCloudRepositories repositories;

	public BBCloudApi(BBCloudIntegrationEntity apiEntity) {
		this.apiEntity = apiEntity;
		this.comments = new BBCloudComments(apiEntity);
		this.repositories = new BBCloudRepositories(apiEntity);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void testClientConnection() throws ApiIntegrationException {
		HttpResponse<String> resp =
				makeGetRequest(apiEntity.makeApiWorkspaceUrl(), null).asString();
		if (resp.getStatus() != HttpStatus.OK.value()) {
			throw new ApiIntegrationException(
					"Client received " + resp.getStatus() + " while accessing workspace");
		}
		Integer numRepos = JsonPath.parse(resp.getBody()).read("$.pagelen");
		if (numRepos == 0) {
			throw new ApiIntegrationException(
					"Client has access to 0 respositories in workspace");
		}
	}

	/**
	 * {@inheritDoc}
	 * <p>
	 * {@code passwordEncoder} is unused: HMAC verification of incoming deliveries needs the
	 * plaintext secret to recompute the digest, so it is encrypted at rest
	 * ({@link BBCloudIntegrationEntity#getWebhookSecret()}) rather than hashed.
	 * <p>
	 * Registers (or updates, if a matching hook already exists) a single workspace-level
	 * webhook covering every repository in the workspace, per IMPROVEMENT_PLAN.md item 8.
	 */
	@Override
	public void register(PasswordEncoder passwordEncoder, String callbackBaseUrl) {
		String hookUrl = buildRequestUrl(StringUtils.stripEnd(callbackBaseUrl, "/"), "rest",
				"scan", apiEntity.getApiLabel());
		String secret = ensureWebhookSecret();

		JSONObject body = new JSONObject();
		body.put("description", "Watchtower scan webhook");
		body.put("url", hookUrl);
		body.put("active", true);
		body.put("secret", secret);
		body.put("events", new JSONArray(WEBHOOK_EVENTS));

		try {
			String existingUuid = findExistingHookUuid(callbackBaseUrl);
			String targetUrl = existingUuid == null ? apiEntity.makeWorkspaceHooksUrl()
					: buildRequestUrl(apiEntity.makeWorkspaceHooksUrl(), existingUuid);

			HttpResponse<JsonNode> response = submitHook(targetUrl, body, existingUuid == null);
			int retries = 5;
			while (response.getStatus() == 429) {
				handleRateLimiter(response.getHeaders(), retries--);
				response = submitHook(targetUrl, body, existingUuid == null);
			}
			if (response.getStatus() != 200 && response.getStatus() != 201) {
				throw new IllegalStateException(
						"Bad response: " + response.getStatus() + " while registering webhook for "
								+ apiEntity.getApiLabel());
			}
			String uuid = response.getBody().getObject().getString("uuid");
			apiEntity.setWebhookUuid(uuid);
		} catch (UnirestException e) {
			throw new IllegalStateException(
					"Exception while registering webhook for " + apiEntity.getApiLabel(), e);
		}
	}

	private HttpResponse<JsonNode> submitHook(String url, JSONObject body, boolean create) {
		HttpRequestWithBody request = create ? makePostRequest(url, null) : makePutRequest(url, null);
		return request.header("content-type", "application/json").body(body).asJson();
	}

	/**
	 * {@inheritDoc}
	 * <p>
	 * Idempotent: if no webhook was ever registered (or a previous unregister already ran),
	 * there is nothing to delete on Bitbucket's side and this returns without error.
	 */
	@Override
	public void unregister() {
		String uuid = apiEntity.getWebhookUuid();
		if (StringUtils.isBlank(uuid)) {
			return;
		}
		String url = buildRequestUrl(apiEntity.makeWorkspaceHooksUrl(), uuid);
		try {
			HttpResponse<String> response = makeDeleteRequest(url, null).asString();
			int retries = 5;
			while (response.getStatus() == 429) {
				handleRateLimiter(response.getHeaders(), retries--);
				response = makeDeleteRequest(url, null).asString();
			}
			// 404 means the hook is already gone (e.g. deleted directly in Bitbucket) -
			// unregister should still succeed rather than get stuck in FAILED forever.
			if (response.getStatus() != 204 && response.getStatus() != 404) {
				throw new IllegalStateException(
						"Bad response: " + response.getStatus() + " while unregistering webhook for "
								+ apiEntity.getApiLabel());
			}
		} catch (UnirestException e) {
			throw new IllegalStateException(
					"Exception while unregistering webhook for " + apiEntity.getApiLabel(), e);
		}
		apiEntity.setWebhookUuid(null);
		// Repository hooks (including ones configured outside Watchtower) share this secret.
		// A cache cannot prove they are all gone; only explicit rotation may replace it.
	}

	/**
	 * Generates a fresh, high-entropy secret for signing this integration's webhook
	 * deliveries.
	 *
	 * @return a URL-safe, unpadded base64-encoded random secret
	 */
	private static String generateWebhookSecret() {
		byte[] bytes = new byte[WEBHOOK_SECRET_BYTES];
		SECURE_RANDOM.nextBytes(bytes);
		return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
	}

	/** Prepare before persisting and before any remote mutation. Does not rotate an existing secret. */
	public String ensureWebhookSecret() {
		if (StringUtils.isBlank(apiEntity.getWebhookSecret())) {
			String secret = generateWebhookSecret();
			apiEntity.setWebhookSecret(secret);
			return secret;
		}
		return apiEntity.getWebhookSecret();
	}

	/** Read workspace hooks live. Failures never masquerade as an empty listing. */
	public List<BBCloudWebhook> listWorkspaceHooks(String callbackBaseUrl) {
		return listHooks(apiEntity.makeWorkspaceHooksUrl(), callbackBaseUrl);
	}

	/** Read a single repository, without an expensive workspace-wide repository crawl. */
	public List<BBCloudWebhook> listRepoHooks(String slug, String callbackBaseUrl) {
		return listHooks(apiEntity.makeRepoHooksUrl(slug), callbackBaseUrl);
	}

	public record HookMutation(String outcome, String uuid) { }

	/** Read-through ownership checks protect foreign hooks even when the cached row is stale. */
	public HookMutation upsertHook(String slug, String callbackBaseUrl, List<String> events,
			boolean active, String uuid, boolean forceSecret) {
		List<BBCloudWebhook> hooks = slug == null ? listWorkspaceHooks(callbackBaseUrl) : listRepoHooks(slug, callbackBaseUrl);
		BBCloudWebhook found = uuid == null ? hooks.stream().filter(BBCloudWebhook::owned).findFirst().orElse(null)
				: hooks.stream().filter(h -> h.uuid().equals(uuid)).findFirst().orElseThrow(() -> new BBWebhookException(404, 0));
		if (found != null && !found.owned()) throw new IllegalArgumentException("Foreign hooks are read only");
		if (found != null && !forceSecret && found.secretSet() && found.active() == active
				&& new HashSet<>(found.events()).equals(new HashSet<>(events))) return new HookMutation("UNCHANGED", found.uuid());
		if (found == null && slug != null && hooks.size() >= 50) throw new BBWebhookException(409, 0);
		String base = slug == null ? apiEntity.makeWorkspaceHooksUrl() : apiEntity.makeRepoHooksUrl(slug);
		String url = found == null ? base : hookItemUrl(base, found.uuid());
		JSONObject body = new JSONObject().put("description", "Watchtower scan webhook")
				.put("url", buildRequestUrl(StringUtils.stripEnd(callbackBaseUrl, "/"), "rest", "scan", apiEntity.getApiLabel()))
				.put("events", new JSONArray(events)).put("active", active).put("secret", ensureWebhookSecret());
		try {
			HttpRequestWithBody request = found == null ? makePostRequest(url, null) : makePutRequest(url, null);
			HttpResponse<JsonNode> response = request.header("content-type", "application/json")
					.connectTimeout(5000).socketTimeout(15000).body(body).asJson();
			if (response.getStatus() != 200 && response.getStatus() != 201) throw webhookFailure(response);
			return new HookMutation(found == null ? "CREATED" : "UPDATED", response.getBody().getObject().getString("uuid"));
		} catch (UnirestException e) { throw new BBWebhookException(502, 0); }
	}

	public void deleteHook(String slug, String callbackBaseUrl, String uuid) {
		List<BBCloudWebhook> hooks = slug == null ? listWorkspaceHooks(callbackBaseUrl) : listRepoHooks(slug, callbackBaseUrl);
		BBCloudWebhook found = hooks.stream().filter(h -> h.uuid().equals(uuid)).findFirst().orElse(null);
		if (found == null) return;
		if (!found.owned()) throw new IllegalArgumentException("Foreign hooks are read only");
		String base = slug == null ? apiEntity.makeWorkspaceHooksUrl() : apiEntity.makeRepoHooksUrl(slug);
		try {
			HttpResponse<String> response = makeDeleteRequest(hookItemUrl(base, uuid), null)
					.connectTimeout(5000).socketTimeout(15000).asString();
			if (response.getStatus() != 204 && response.getStatus() != 404) throw webhookFailure(response);
		} catch (UnirestException e) { throw new BBWebhookException(502, 0); }
	}

	private String hookItemUrl(String base, String uuid) {
		if (StringUtils.isBlank(uuid) || !uuid.matches("[A-Za-z0-9{}_\\-]+")) throw new IllegalArgumentException("Invalid hook UUID");
		// Bitbucket UUIDs are written {xxxxxxxx-...}. A raw brace is an illegal URL character, so the HTTP client
		// refuses the request before sending it; the braces travel percent-encoded.
		return base + "/" + uuid.replace("{", "%7B").replace("}", "%7D");
	}

	private BBWebhookException webhookFailure(HttpResponse<?> response) {
		return new BBWebhookException(response.getStatus(), response.getStatus() == 429 ? parseRetryAfterSeconds(response.getHeaders()) : 0);
	}

	private List<BBCloudWebhook> listHooks(String collectionUrl, String callbackBaseUrl) {
		String callbackUrl = buildRequestUrl(StringUtils.stripEnd(callbackBaseUrl, "/"),
				"rest", "scan", apiEntity.getApiLabel());
		List<BBCloudWebhook> hooks = new ArrayList<>();
		Set<String> visited = new HashSet<>();
		String url = collectionUrl;
		long deadline = System.nanoTime() + java.time.Duration.ofSeconds(45).toNanos();
		while (StringUtils.isNotBlank(url)) {
			// Never forward integration credentials to a provider-supplied arbitrary next URL.
			if (System.nanoTime() > deadline || !sameCollection(collectionUrl, url) || !visited.add(url) || visited.size() > 100) {
				throw new IllegalStateException("Invalid Bitbucket webhook pagination");
			}
			HttpResponse<JsonNode> response = makeGetRequest(url, null)
					.connectTimeout(5000).socketTimeout(15000).asJson();
			if (response.getStatus() != 200) {
				throw new BBWebhookException(response.getStatus(),
						response.getStatus() == 429 ? parseRetryAfterSeconds(response.getHeaders()) : 0);
			}
			JSONObject responseBody = response.getBody().getObject();
			JSONArray values = responseBody.getJSONArray("values");
			for (int i = 0; i < values.length(); i++) {
				hooks.add(BBCloudWebhook.from(values.getJSONObject(i), callbackUrl));
			}
			if (hooks.size() > 10000) {
				throw new IllegalStateException("Bitbucket webhook listing is too large");
			}
			url = responseBody.optString("next", null);
		}
		return List.copyOf(hooks);
	}

	private static boolean sameCollection(String collectionUrl, String pageUrl) {
		try {
			URI collection = URI.create(collectionUrl);
			URI page = URI.create(pageUrl);
			return collection.getScheme().equals(page.getScheme())
					&& collection.getRawAuthority().equals(page.getRawAuthority())
					&& collection.getRawPath().equals(page.getRawPath())
					&& page.getRawUserInfo() == null && page.getRawFragment() == null;
		} catch (IllegalArgumentException e) {
			return false;
		}
	}

	private String findExistingHookUuid(String callbackBaseUrl) {
		return listWorkspaceHooks(callbackBaseUrl).stream().filter(BBCloudWebhook::owned)
				.map(BBCloudWebhook::uuid).findFirst().orElse(null);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public boolean testConnectionForPullRequest(PullRequest pullRequest) {
		boolean connected = false;
		String prBase = apiEntity.makeApiPRUrl(pullRequest.getRepoName(), pullRequest.getPrId());
		String url = buildRequestUrl(prBase);
		try {
			HttpResponse<String> response = makeGetRequest(url, null).asString();
			int retries = 5;
			while (response.getStatus() == 429) {
				handleRateLimiter(response.getHeaders(), retries--);
				response = makeGetRequest(url, null).asString();
			}
			if (response.getStatus() == 200) {
				connected = true;
			} else {
				LOG.error("Bad response: " + response.getStatus()
						+ " while testing connection for PR "
						+ pullRequest.getPRString());
				LOG.debug("Response body: {}",
						StringUtils.abbreviate(String.valueOf(response.getBody()), MAX_LOGGED_BODY));
			}
		} catch (UnirestException e) {
			LOG.error("Exception while connecting to Bitbucket for PR " + pullRequest.getPRString(),
					e);
		}
		return connected;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void downloadSourceForPullRequest(PullRequest pullRequest, Path targetDirectory)
			throws IOException {
		downloadSource(pullRequest.getRepoName(), pullRequest.getCommitHash(), targetDirectory,
				pullRequest.getPRString(), SourceDownloadLimits.SCAN);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void downloadSource(String repoName, String commitHash, Path targetDirectory)
			throws IOException {
		downloadSource(repoName, commitHash, targetDirectory,
				repoName + "@" + StringUtils.left(commitHash, 7), SourceDownloadLimits.SCAN);
	}

	@Override
	public void downloadSource(String repoName, String commitHash, Path targetDirectory, SourceDownloadLimits limits) throws IOException {
		downloadSource(repoName, commitHash, targetDirectory, repoName + "@" + StringUtils.left(commitHash, 7), limits);
	}

	private void downloadSource(String repoName, String commitHash, Path targetDirectory,
			String context, SourceDownloadLimits limits) throws IOException {
        Path tempFile = null, tempDir = null;
        try {
            Path parent = targetDirectory.toAbsolutePath().getParent();
            tempFile = Files.createTempFile(parent, "source-", ".zip");
            String url = apiEntity.makeDownloadLink(repoName, commitHash);
            long deadline = System.nanoTime() + java.time.Duration.ofSeconds(limits.equals(SourceDownloadLimits.ASSISTANT) ? 90 : 300).toNanos();
            IOException lastFailure = null;
            for (int attempt = 1; attempt <= MAX_DOWNLOAD_ATTEMPTS; attempt++) {
                if (System.nanoTime() > deadline) throw new IOException("Source download deadline exceeded");
                lastFailure = attemptDownload(url, tempFile, limits.archiveBytes(), deadline);
                if (lastFailure == null) {
                    LOG.info("Downloaded source for {} in {} attempt(s), {} bytes", context, attempt, Files.size(tempFile));
                    break;
                }
                LOG.warn("Source download failed (attempt {} of {}): {}", attempt, MAX_DOWNLOAD_ATTEMPTS, lastFailure.getMessage());
                if (lastFailure instanceof SourceLimitException) break;
            }
            if (lastFailure != null) throw lastFailure;
            tempDir = Files.createTempDirectory(parent, "source-extract-");
            try (var zip = new java.util.zip.ZipFile(tempFile.toFile())) {
                SecureZipUtils.secureUnzip(zip, tempDir.toFile(), limits.extractedBytes(), limits.entries(), 100);
            }
            promoteExtractedRoot(tempDir, targetDirectory, context);
        } finally {
            if (tempDir != null) FileUtils.deleteQuietly(tempDir.toFile());
            if (tempFile != null) FileUtils.deleteQuietly(tempFile.toFile());
        }
    }

	/**
	 * Moves the root of an extracted source archive to the working directory.
	 * <p>
	 * A Bitbucket source archive wraps everything in a single root directory named for
	 * the repository and commit, so the working directory becomes that root's contents
	 * rather than the root itself.
	 * <p>
	 * @param extractedDir    the directory the archive was extracted into
	 * @param targetDirectory the working directory to move the archive root onto
	 * @param context         what is being downloaded, for error messages
	 * @throws IOException if the archive extracted to nothing, or the move fails
	 */
	private void promoteExtractedRoot(Path extractedDir, Path targetDirectory,
			String context) throws IOException {
		Path extractedRoot;
		try (Stream<Path> entries = Files.list(extractedDir)) {
			// Finder-created fixtures can have a separate metadata directory; never promote it.
			var roots = entries.filter(p -> !p.getFileName().toString().equals("__MACOSX")).toList();
			if (roots.size() != 1 || !Files.isDirectory(roots.getFirst()) || Files.isSymbolicLink(roots.getFirst())) throw new IOException("Source archive must contain exactly one directory root");
			extractedRoot = roots.getFirst();
		}
		LOG.debug("Promoting extracted root '" + extractedRoot.getFileName()
				+ "' to the working directory for " + context);
		FileUtils.deleteQuietly(targetDirectory.toFile());
		// Files.move rather than File.renameTo: renameTo reports failure through a
		// boolean that is easy to drop, and a silently failed move leaves an empty
		// working directory, which a scan reports as "no violations found".
		Files.move(extractedRoot, targetDirectory);
	}

	/**
	 * Makes a single attempt to download the source zip to the given file.
	 * <p>
	 * The output stream truncates on open, so a partial body left behind by a failed
	 * attempt is never prepended to the body of a later successful one.
	 *
	 * @param url      the download url to fetch
	 * @param tempFile the file to write the zip content into
	 * @return null if the download succeeded, otherwise the exception describing why it
	 *         failed
	 * @throws IOException if the output file cannot be opened or closed
	 */
	private IOException attemptDownload(String url, Path tempFile, long maxBytes, long deadline) throws IOException {
		AtomicReference<IOException> failure = new AtomicReference<>(null);
		try (OutputStream out = Files.newOutputStream(tempFile, StandardOpenOption.WRITE,
				StandardOpenOption.TRUNCATE_EXISTING)) {
			makeGetRequest(url, null)
					.connectTimeout(5000).socketTimeout(15000)
					.thenConsume(r -> {
						try {
							if (r.getStatus() != 200) {
								throw new IOException("Response code is " + r.getStatus());
							}
							try (var in = r.getContent()) {
								byte[] buffer = new byte[8192]; long total = 0; int size;
								while ((size = in.read(buffer)) != -1) {
									if ((total += size) > maxBytes) throw new SourceLimitException("Source archive exceeds download limit");
									if (System.nanoTime() > deadline) throw new SourceLimitException("Source download deadline exceeded");
									out.write(buffer, 0, size);
								}
							}
						} catch (IOException ex) {
							failure.set(ex);
						}
					});
		} catch (UnirestException e) { return new IOException("Source transport unavailable"); }
		return failure.get();
	}
	private static final class SourceLimitException extends IOException {
		SourceLimitException(String message) { super(message); }
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public DiffFile getGitDiffFile(PullRequest pullRequest, String filePath) {
		DiffFile gitFile = null;
		String prBase = apiEntity.makeApiPRUrl(pullRequest.getRepoName(), pullRequest.getPrId());
		String url = buildRequestUrl(prBase, "diff");
		Map<String, Object> params = new HashMap<String, Object>();
		params.put("path", filePath);
		// Only the changed line numbers are used, so no surrounding context is needed.
		// This relies on DiffFile.parseDiff() reading hunk headers - it previously
		// counted from line 1, which only worked because a huge context value collapsed
		// the response into a single hunk starting at line 1.
		params.put("context", "0");
		try {
			HttpResponse<byte[]> response = makeGetRequest(url, params).asBytes();
			int retries = 5;
			while (response.getStatus() == 429) {
				handleRateLimiter(response.getHeaders(), retries--);
				response = makeGetRequest(url, params).asBytes();
			}

			if (response.getStatus() == 200) {
				gitFile = new DiffFile(filePath, pullRequest.getPRString());
				gitFile.parseDiff(new ByteArrayInputStream(response.getBody()));
				// Response size is the visible proof that context=0 took effect: these
				// should be hundreds of bytes, not the whole file body.
				LOG.debug("Fetched diff for " + filePath + " with context=0: "
						+ response.getBody().length + " bytes, "
						+ gitFile.getModifiedLineCount() + " changed line(s)");
			} else if (response.getStatus() == 555) {
				LOG.error("Bad response (repo timed out): " + response.getStatus()
						+ " while getting git diff file "
						+ filePath + " for PR " + pullRequest.getPRString());
			} else {
				LOG.error("Bad response: " + response.getStatus() + " while getting git diff file "
						+ filePath
						+ " for PR " + pullRequest.getPRString());
				LOG.debug(new String(response.getBody()));
			}
		} catch (IOException e) {
			LOG.error(
					"Exception while streaming git diff file " + filePath + " for PR "
							+ pullRequest.getPRString(),
					e);
		} catch (UnirestException e) {
			LOG.error("Exception while getting git diff file " + filePath + " for PR "
					+ pullRequest.getPRString(), e);
		}
		return gitFile;
	}

	/**
	 * {@inheritDoc}
	 * <p>
	 * Uses the pull request's source branch as the revision, not a commit hash: unlike
	 * {@link #downloadFileAtCommit}, which runs during scanning when a freshly-resolved commit
	 * hash is available on the {@link PullRequest} in hand, this is called at report-view time,
	 * potentially long after the scan, when only the branch name survives in the database
	 * (PullRequestContainerEntity has no commit-hash column). Bitbucket's src endpoint accepts
	 * either interchangeably. Content shown here is therefore the branch's current state, which
	 * may have moved since the scan ran if the PR was pushed to again - not a frozen snapshot of
	 * what was actually scanned.
	 */
	@Override
	public String getFileContent(PullRequest pullRequest, String filePath) {
		String url = apiEntity.makeSourceFileUrl(pullRequest.getRepoName(),
				pullRequest.getSourceBranch(), filePath);
		try {
			HttpResponse<byte[]> response = makeGetRequest(url, null).asBytes();
			int retries = 5;
			while (response.getStatus() == 429) {
				handleRateLimiter(response.getHeaders(), retries--);
				response = makeGetRequest(url, null).asBytes();
			}

			if (response.getStatus() == 200) {
				return new String(response.getBody(), StandardCharsets.UTF_8);
			} else if (response.getStatus() == 404) {
				// Not an error worth logging at ERROR: the file may simply have been
				// deleted, renamed, or moved to a different branch since the scan ran.
				LOG.debug("File " + filePath + " not found on branch "
						+ pullRequest.getSourceBranch() + " for " + pullRequest.getPRString());
			} else {
				LOG.error("Bad response: " + response.getStatus()
						+ " while getting file content for " + filePath + " for PR "
						+ pullRequest.getPRString());
			}
		} catch (UnirestException e) {
			LOG.error("Exception while getting file content for " + filePath + " for PR "
					+ pullRequest.getPRString(), e);
		}
		return null;
	}

	/**
	 * Bitbucket Cloud gives a pull request's source and destination commits as 12-character hashes; the commit
	 * endpoint completes one. The hash returned must start with the one asked for.
	 */
	@Override
	public String fullCommit(String repository, String commit) throws IOException {
		if (commit != null && commit.matches("[a-fA-F0-9]{40,64}")) return commit;
		if (commit == null || !commit.matches("[a-fA-F0-9]{7,39}")) throw new IOException("A commit hash is required");
		byte[] json = boundedScmRead(buildRequestUrl(apiEntity.makeApiRepoUrl(repository), "commit", commit), 65536);
		String hash;
		try {
			hash = new JSONObject(new String(json, java.nio.charset.StandardCharsets.UTF_8)).getString("hash");
		} catch (RuntimeException e) { throw new IOException("Commit unavailable"); }
		validatePinnedRef(hash);
		if (!hash.toLowerCase(java.util.Locale.ROOT).startsWith(commit.toLowerCase(java.util.Locale.ROOT))) throw new IOException("The commit found is not the one asked for");
		return hash;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public String mergeBase(String repository, String head, String base) throws IOException {
		validatePinnedRef(head); validatePinnedRef(base);
		byte[] json = boundedScmRead(buildRequestUrl(apiEntity.makeApiRepoUrl(repository), "merge-base", head + ".." + base), 65536);
		try {
			String hash = new JSONObject(new String(json, java.nio.charset.StandardCharsets.UTF_8)).getString("hash");
			validatePinnedRef(hash); return hash;
		} catch (RuntimeException e) { throw new IOException("Merge base unavailable"); }
	}

	@Override
	public byte[] rawDiff(String repository, String head, String mergeBase, int maxBytes) throws IOException {
		validatePinnedRef(head); validatePinnedRef(mergeBase);
		if (maxBytes < 1 || maxBytes > 5 * 1024 * 1024) throw new IOException("Invalid diff bound");
		// Bitbucket's order is head..base, the reverse of git diff.
		return boundedScmRead(buildRequestUrl(apiEntity.makeApiRepoUrl(repository), "diff", head + ".." + mergeBase), maxBytes);
	}

    @Override
    public byte[] boundedFileAtCommit(String repository, String commit, String file, int maxBytes) throws IOException {
        validatePinnedRef(commit);
        if (maxBytes < 1 || maxBytes > 8 * 1024 * 1024 || !com.tracelink.appsec.watchtower.core.scan.code.report.ProviderFindingDetails.Location.valid(file, 1, 1))
            throw new IOException("Invalid source path or bound");
        return boundedScmRead(apiEntity.makeSourceFileUrl(repository, commit, file), maxBytes);
    }

	private static void validatePinnedRef(String ref) throws IOException {
		if (ref == null || !ref.matches("[a-fA-F0-9]{40,64}")) throw new IOException("A full pinned commit is required");
	}

	private byte[] boundedScmRead(String url, int maxBytes) throws IOException {
		var output = new java.io.ByteArrayOutputStream();
		var failure = new AtomicReference<IOException>();
		long deadline = System.nanoTime() + java.time.Duration.ofSeconds(60).toNanos();
		try {
			makeGetRequest(url, null).connectTimeout(5000).socketTimeout(15000).thenConsume(r -> {
				try (var input = r.getContent()) {
					if (r.getStatus() != 200) throw new IOException("Pinned SCM input unavailable: HTTP " + r.getStatus());
					byte[] buffer = new byte[8192]; int n;
					while ((n = input.read(buffer)) != -1) {
						if (output.size() + n > maxBytes || System.nanoTime() > deadline) throw new IOException("Pinned SCM input exceeds limits");
						output.write(buffer, 0, n);
					}
				} catch (IOException e) { failure.set(e); }
			});
		} catch (UnirestException e) { throw new IOException("Pinned SCM transport unavailable"); }
		if (failure.get() != null) throw failure.get();
		return output.toByteArray();
	}

	@Override
	public Map<String, DiffFile> getChangedFilesForPullRequest(PullRequest pullRequest) {
		String prBase = apiEntity.makeApiPRUrl(pullRequest.getRepoName(), pullRequest.getPrId());
		String url = buildRequestUrl(prBase, "diff");
		Map<String, Object> params = new HashMap<String, Object>();
		// No "path" param, unlike getGitDiffFile(): this fetches every changed file's diff
		// in one call. Same context=0 reasoning as getGitDiffFile - only line numbers matter.
		params.put("context", "0");
		try {
			HttpResponse<byte[]> response = makeGetRequest(url, params).asBytes();
			int retries = 5;
			while (response.getStatus() == 429) {
				if (retries == 0) {
					// IMPROVEMENT_PLAN.md item 4.7: unlike handleRateLimiter()'s other
					// callers (webhook register/unregister, PullRequestSynchronizer's
					// polling), this method is on PRScanAgent.collectFiles()'s critical
					// path for every scan regardless of scope. Once the bounded blocking
					// retry above is exhausted, throw a retriable signal instead of
					// giving up, so PRScanAgent.handleScanException() (when running
					// under SQS - see item 4.5) can re-enqueue the scan for a fresh
					// attempt later, rather than losing it.
					throw new RateLimitedException(parseRetryAfterSeconds(response.getHeaders()));
				}
				handleRateLimiter(response.getHeaders(), retries--);
				response = makeGetRequest(url, params).asBytes();
			}

			if (response.getStatus() == 200) {
				Map<String, DiffFile> diffs = DiffFile.parseMultiFileDiff(
						new ByteArrayInputStream(response.getBody()), pullRequest.getPRString());
				LOG.debug("Fetched diff for " + pullRequest.getPRString() + " with context=0: "
						+ response.getBody().length + " bytes, " + diffs.size()
						+ " changed file(s)");
				return diffs;
			} else if (response.getStatus() == 555) {
				LOG.error("Bad response (repo timed out): " + response.getStatus()
						+ " while getting changed files for PR " + pullRequest.getPRString());
			} else {
				LOG.error("Bad response: " + response.getStatus()
						+ " while getting changed files for PR " + pullRequest.getPRString());
				LOG.debug(new String(response.getBody()));
			}
		} catch (IOException e) {
			LOG.error("Exception while streaming changed files for PR "
					+ pullRequest.getPRString(), e);
		} catch (UnirestException e) {
			LOG.error("Exception while getting changed files for PR "
					+ pullRequest.getPRString(), e);
		}
		return Collections.emptyMap();
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void downloadFileAtCommit(PullRequest pullRequest, String filePath,
			Path targetDirectory) throws IOException {
		downloadFileAtCommit(pullRequest.getRepoName(), pullRequest.getCommitHash(), filePath,
				targetDirectory, pullRequest.getPRString());
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void downloadFileAtCommit(String repoName, String commitHash, String filePath,
			Path targetDirectory) throws IOException {
		downloadFileAtCommit(repoName, commitHash, filePath, targetDirectory,
				repoName + "@" + StringUtils.left(commitHash, 7));
	}

	private void downloadFileAtCommit(String repoName, String commitHash, String filePath,
			Path targetDirectory, String context) throws IOException {
		// filePath comes from a diff this class itself fetched, but it is still resolved and
		// bounds-checked before any write - the same discipline as accepting untrusted input,
		// since a malformed diff entry (e.g. containing "../") must not write outside the
		// working directory.
		Path target = targetDirectory.resolve(filePath).normalize();
		if (!target.startsWith(targetDirectory.normalize())) {
			throw new IOException(
					"Refusing to write '" + filePath + "' outside the working directory");
		}

		String url = apiEntity.makeSourceFileUrl(repoName, commitHash, filePath);
		HttpResponse<byte[]> response = makeGetRequest(url, null).asBytes();
		int retries = 5;
		while (response.getStatus() == 429) {
			if (retries == 0) {
				// IMPROVEMENT_PLAN.md item 4.7 - see getChangedFilesForPullRequest()'s
				// identical reasoning for why this call site (also on
				// PRScanAgent.collectFiles()'s critical path) throws instead of giving
				// up once the bounded blocking retry above is exhausted.
				throw new RateLimitedException(parseRetryAfterSeconds(response.getHeaders()));
			}
			try {
				handleRateLimiter(response.getHeaders(), retries--);
			} catch (UnirestException e) {
				throw new IOException(e);
			}
			response = makeGetRequest(url, null).asBytes();
		}

		if (response.getStatus() == 404) {
			// The file existed in the diff but is gone by the time we fetch it - deleted
			// later in the PR, or the commit moved on. Not an error: the caller simply will
			// not find this file in the working directory.
			LOG.debug("File " + filePath + " not found at commit " + commitHash
					+ " for " + context + "; skipping");
			return;
		}
		if (response.getStatus() != 200) {
			throw new IOException("Response code is " + response.getStatus() + " for " + filePath
					+ " in " + context);
		}

		if (target.getParent() != null) {
			Files.createDirectories(target.getParent());
		}
		Files.write(target, response.getBody(), StandardOpenOption.CREATE,
				StandardOpenOption.TRUNCATE_EXISTING);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public List<String> listFilesAtCommit(PullRequest pullRequest) {
		List<String> files = new ArrayList<>();
		// max_depth requests the whole recursive tree instead of Bitbucket's default
		// single-level listing, so this follows "next" pagination links rather than
		// making a separate request per directory.
		Map<String, Object> params = new HashMap<>();
		params.put("max_depth", "9999");
		params.put("pagelen", "100");
		String url = apiEntity.makeSourceListingUrl(pullRequest.getRepoName(),
				pullRequest.getCommitHash());
		try {
			while (url != null) {
				HttpResponse<JsonNode> response = makeGetRequest(url, params).asJson();
				int retries = 5;
				while (response.getStatus() == 429) {
					handleRateLimiter(response.getHeaders(), retries--);
					response = makeGetRequest(url, params).asJson();
				}
				if (response.getStatus() == 404) {
					// The commit itself is gone by the time this runs (e.g. force-pushed
					// away) - nothing to list, not an error.
					LOG.debug("No source found at commit " + pullRequest.getCommitHash()
							+ " for " + pullRequest.getPRString());
					return Collections.emptyList();
				}
				if (response.getStatus() != 200) {
					// A partial listing is as dangerous as a guessed one (the whole point
					// of this method is to avoid silently missing files), so a failure on
					// any page discards everything collected so far rather than returning
					// an incomplete list disguised as complete.
					LOG.error("Bad response: " + response.getStatus()
							+ " while listing files at commit " + pullRequest.getCommitHash()
							+ " for " + pullRequest.getPRString());
					return Collections.emptyList();
				}
				JSONObject responseBody = response.getBody().getObject();
				JSONArray values = responseBody.getJSONArray("values");
				for (int i = 0; i < values.length(); i++) {
					JSONObject value = values.getJSONObject(i);
					if ("commit_file".equals(value.optString("type"))) {
						files.add(value.getString("path"));
					}
				}
				// "next" is a full url with its own query params already applied, so only
				// the first request needs max_depth/pagelen supplied explicitly.
				url = responseBody.optString("next", null);
				params = null;
			}
		} catch (UnirestException e) {
			LOG.error("Exception while listing files at commit " + pullRequest.getCommitHash()
					+ " for " + pullRequest.getPRString(), e);
			return Collections.emptyList();
		}
		return files;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public PullRequest updatePRData(PullRequest pullRequest) throws ScanRejectedException {
		if (StringUtils.isBlank(pullRequest.getRepoName())
				|| StringUtils.isBlank(pullRequest.getPrId())) {
			LOG.error("Pull Request does not have enough information to get the rest of the data");
			throw new ScanRejectedException(
					"Pull Request does not have enough information to get the rest of the data");
		}
		String prBase = apiEntity.makeApiPRUrl(pullRequest.getRepoName(), pullRequest.getPrId());
		String prUrl = buildRequestUrl(prBase);
		BBPullRequest bbpr = new BBPullRequest(pullRequest.getApiLabel());
		bbpr.setRepoName(pullRequest.getRepoName());
		bbpr.setPrId(pullRequest.getPrId());
		LOG.debug("Requesting PR data for " + pullRequest.getPRString() + " from " + prUrl
				+ " (apiLabel=" + apiEntity.getApiLabel() + ", workspace="
				+ apiEntity.getWorkspace() + ", user=" + apiEntity.getUser() + ")");
		try {
			HttpResponse<String> response = makeGetRequest(prUrl, null).asString();
			int retries = 5;
			while (response.getStatus() == 429) {
				handleRateLimiter(response.getHeaders(), retries--);
				response = makeGetRequest(prUrl, null).asString();
			}
			if (response.getStatus() == 200) {
				String prData = response.getBody();
				bbpr.parsePullRequestJson(prData);
			} else if (response.getStatus() == HttpStatus.NOT_FOUND.value()) {
				// Permanent: the Pull Request is gone, or its id was never valid. Callers
				// need this distinguishable from a timeout so they can stop re-polling a
				// row that can never succeed.
				throw new PullRequestNotFoundException("Bitbucket reports no such Pull Request: "
						+ pullRequest.getPRString());
			} else {
				LOG.error("Bad response: " + response.getStatus()
						+ " while getting more Pull Request information for PR "
						+ pullRequest.getPRString() + " (apiLabel=" + apiEntity.getApiLabel()
						+ ", workspace=" + apiEntity.getWorkspace() + ", user="
						+ apiEntity.getUser() + ")");
				LOG.debug("Response body: {}",
						StringUtils.abbreviate(String.valueOf(response.getBody()), MAX_LOGGED_BODY));
			}
		} catch (UnirestException e) {
			LOG.error("Exception while getting more Pull Request information for PR "
					+ pullRequest.getPRString(), e);
		}

		if (!bbpr.hasAllData()) {
			throw new ScanRejectedException("Could not fill all PR Data");
		}
		return bbpr;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public boolean sendComment(PullRequest pullRequest, String comment) {
		switch (apiEntity.getRejectOption()) {
			case DO_NOTHING:
				LOG.info("Skipping sending comment due to Integration Setting "
						+ apiEntity.getRejectOption().getName());
				return true;
			case BLOCK_PR:
			case SEND_COMMENT:
			case APPROVE_OR_REQUEST_CHANGES:
				break;
			default:
				throw new IllegalArgumentException("Unknown Integration Entity rejection option");
		}
		String prBase = apiEntity.makeApiPRUrl(pullRequest.getRepoName(), pullRequest.getPrId());
		String url = buildRequestUrl(prBase, "comments");

		JSONObject raw = new JSONObject().put("raw", comment);
		JSONObject body = new JSONObject().put("content", raw);

		try {
			HttpRequestWithBody bb = makePostRequest(url, null);
			HttpResponse<String> response =
					bb.header("content-type", "application/json").body(body).asString();
			int retries = 5;
			while (response.getStatus() == 429) {
				handleRateLimiter(response.getHeaders(), retries--);
				bb = makePostRequest(url, null);
				response = bb.header("content-type", "application/json").body(body).asString();
			}

			if (response.getStatus() != 201) {
				LOG.error("Bad response: " + response.getStatus() + " while sending report for PR "
						+ pullRequest.getPRString());
				LOG.debug("Response body: {}",
						StringUtils.abbreviate(String.valueOf(response.getBody()), MAX_LOGGED_BODY));
				return false;
			}
			return true;
		} catch (UnirestException e) {
			LOG.error("Exception while sending report for PR " + pullRequest.getPRString(), e);
			return false;
		}
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public List<PullRequestComment> listComments(PullRequest pullRequest) {
		return commentsDisabled() ? List.of() : comments.list(pullRequest);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public boolean sendInlineComment(PullRequest pullRequest, String path, int line,
			String comment) {
		return commentsDisabled() || comments.postInline(pullRequest, path, line, comment);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public boolean keepsBlockedPullRequestsOpen() {
		return apiEntity.getRejectOption() != BBCloudRejectOption.BLOCK_PR;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public boolean replyToComment(PullRequest pullRequest, long commentId, String comment) {
		return commentsDisabled() || comments.reply(pullRequest, commentId, comment);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public boolean updateComment(PullRequest pullRequest, long commentId, String comment) {
		return commentsDisabled() || comments.update(pullRequest, commentId, comment);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public boolean deleteComment(PullRequest pullRequest, long commentId) {
		return commentsDisabled() || comments.delete(pullRequest, commentId);
	}

	/**
	 * @return true if the integration is configured not to comment, as {@link #sendComment}
	 */
	private boolean commentsDisabled() {
		return apiEntity.getRejectOption() == BBCloudRejectOption.DO_NOTHING;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public boolean blockPR(PullRequest pullRequest) {
		switch (apiEntity.getRejectOption()) {
			case DO_NOTHING:
			case SEND_COMMENT:
			case APPROVE_OR_REQUEST_CHANGES:
				LOG.info("Skipping declining PR due to Integration Setting "
						+ apiEntity.getRejectOption().getName());
				return true;
			case BLOCK_PR:
				break;
			default:
				throw new IllegalArgumentException("Unknown Integration Entity rejection option");
		}
		String prBase = apiEntity.makeApiPRUrl(pullRequest.getRepoName(), pullRequest.getPrId());
		String url = buildRequestUrl(prBase, "decline");

		try {
			HttpResponse<String> response = makePostRequest(url, null).asString();

			int retries = 5;
			while (response.getStatus() == 429) {
				handleRateLimiter(response.getHeaders(), retries--);
				response = makePostRequest(url, null).asString();
			}

			if (response.getStatus() != 200) {
				LOG.error("Bad response: " + response.getStatus() + " while declining PR "
						+ pullRequest.getPRString());
				LOG.debug("Response body: {}",
						StringUtils.abbreviate(String.valueOf(response.getBody()), MAX_LOGGED_BODY));
				return false;
			}
			return true;
		} catch (UnirestException e) {
			LOG.error("Exception while declining PR " + pullRequest.getPRString(), e);
			return false;
		}
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public boolean approvePR(PullRequest pullRequest) {
		if (!managesReviewState()) {
			return true;
		}
		HeadState head = headState(pullRequest);
		if (head != HeadState.CURRENT) {
			return head == HeadState.MOVED;
		}
		String prBase = apiEntity.makeApiPRUrl(pullRequest.getRepoName(), pullRequest.getPrId());
		try {
			clearReview(buildRequestUrl(prBase, REQUEST_CHANGES_PATH), pullRequest);
			return postReview(buildRequestUrl(prBase, APPROVE_PATH), pullRequest, "approving");
		} catch (UnirestException e) {
			LOG.error("Exception while approving PR " + pullRequest.getPRString(), e);
			return false;
		}
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public boolean requestChangesPR(PullRequest pullRequest) {
		if (!managesReviewState()) {
			return true;
		}
		HeadState head = headState(pullRequest);
		if (head != HeadState.CURRENT) {
			return head == HeadState.MOVED;
		}
		String prBase = apiEntity.makeApiPRUrl(pullRequest.getRepoName(), pullRequest.getPrId());
		try {
			clearReview(buildRequestUrl(prBase, APPROVE_PATH), pullRequest);
			return postReview(buildRequestUrl(prBase, REQUEST_CHANGES_PATH), pullRequest,
					"requesting changes on");
		} catch (UnirestException e) {
			LOG.error("Exception while requesting changes on PR " + pullRequest.getPRString(), e);
			return false;
		}
	}

	private boolean managesReviewState() {
		return apiEntity.getRejectOption() == BBCloudRejectOption.APPROVE_OR_REQUEST_CHANGES;
	}

	/** Whether the scanned commit is still the pull request's head. */
	private enum HeadState {
		CURRENT,
		/** A newer commit was pushed; its own scan sets the review state. */
		MOVED,
		/** The head could not be fetched or compared. */
		UNKNOWN
	}

	/**
	 * Stale-head guard: a scan may finish after a newer commit was pushed, so review state is
	 * only set if the scanned commit is still the PR head. If the head cannot be confirmed,
	 * nothing is changed.
	 */
	private HeadState headState(PullRequest pullRequest) {
		String scanned = pullRequest.getCommitHash();
		String head;
		try {
			head = updatePRData(pullRequest).getCommitHash();
		} catch (ScanRejectedException e) {
			LOG.warn("Cannot confirm head commit for PR " + pullRequest.getPRString()
					+ "; leaving review state unchanged");
			return HeadState.UNKNOWN;
		}
		if (StringUtils.isBlank(scanned) || StringUtils.isBlank(head)) {
			LOG.warn("Cannot confirm head commit for PR " + pullRequest.getPRString()
					+ "; leaving review state unchanged");
			return HeadState.UNKNOWN;
		}
		// Bitbucket returns abbreviated hashes in some payloads; compare as prefixes
		if (scanned.startsWith(head) || head.startsWith(scanned)) {
			return HeadState.CURRENT;
		}
		LOG.info("Skipping review action for PR " + pullRequest.getPRString()
				+ ": a newer commit has been pushed since this scan");
		return HeadState.MOVED;
	}

	/**
	 * Withdraws this account's approval or change request. 404 means there was nothing to
	 * withdraw.
	 */
	private void clearReview(String url, PullRequest pullRequest) throws UnirestException {
		HttpResponse<String> response = makeDeleteRequest(url, null).asString();
		int retries = 5;
		while (response.getStatus() == 429) {
			handleRateLimiter(response.getHeaders(), retries--);
			response = makeDeleteRequest(url, null).asString();
		}
		int status = response.getStatus();
		if (!isSuccess(status) && status != 404) {
			LOG.warn("Bad response: " + status + " while clearing review state for PR "
					+ pullRequest.getPRString());
		}
	}

	private boolean postReview(String url, PullRequest pullRequest, String action)
			throws UnirestException {
		HttpResponse<String> response = makePostRequest(url, null).asString();
		int retries = 5;
		while (response.getStatus() == 429) {
			handleRateLimiter(response.getHeaders(), retries--);
			response = makePostRequest(url, null).asString();
		}
		if (isSuccess(response.getStatus())) {
			LOG.debug("Review action succeeded: " + action + " PR " + pullRequest.getPRString());
			return true;
		}
		LOG.error("Bad response: " + response.getStatus() + " while " + action + " PR "
				+ pullRequest.getPRString());
		return false;
	}

	private static boolean isSuccess(int status) {
		return status >= 200 && status < 300;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public List<PullRequest> getOpenPullRequestsForRepository(String repoName) {
		List<PullRequest> openPrs = new ArrayList<>();
		String url = buildRequestUrl(apiEntity.makeApiWorkspaceUrl(), repoName, "pullrequests");

		try {
			while (url != null) {
				HttpResponse<JsonNode> response =
						makeGetRequest(url, Collections.singletonMap("state", "OPEN")).asJson();

				int retries = 5;
				while (response.getStatus() == 429) {
					handleRateLimiter(response.getHeaders(), retries--);
					response =
							makeGetRequest(url, Collections.singletonMap("state", "OPEN")).asJson();
				}

				if (response.getStatus() != 200) {
					LOG.error("Bad response: " + response.getStatus()
							+ " while getting PRs for repository " + repoName);
					LOG.debug("Response body: {}", StringUtils.abbreviate(
							String.valueOf(response.getBody()), MAX_LOGGED_BODY));
					break;
				}
				JSONObject body = response.getBody().getObject();
				JSONArray values = body.getJSONArray("values");
				for (int i = 0; i < values.length(); i++) {
					JSONObject value = values.getJSONObject(i);
					BBPullRequest bbpr = new BBPullRequest(apiEntity.getApiLabel());
					bbpr.setRepoName(repoName);
					bbpr.parsePullRequestJson(value.toString());

					openPrs.add(bbpr);
				}
				url = body.optString("next", null);
			}
		} catch (UnirestException e) {
			LOG.error("Exception while getting PRs for repository " + repoName, e);
		}

		return openPrs;
	}

	@Override
	public boolean isRepositoryActive(String repoName) {
		boolean active = true;
		String url = buildRequestUrl(apiEntity.makeApiWorkspaceUrl(), repoName);
		try {
			HttpResponse<JsonNode> response = makeGetRequest(url, null).asJson();

			int retries = 5;
			while (response.getStatus() == 429) {
				handleRateLimiter(response.getHeaders(), retries--);
				response = makeGetRequest(url, null).asJson();
			}

			// Only Bitbucket saying the repository does not exist means it is gone: a 401, 403 or
			// 5xx (an expired credential, an outage) says nothing about the repository, and
			// treating it as gone disabled every repository of the integration at once
			active = response.getStatus() != 404;
			if (active && response.getStatus() != 200) {
				LOG.warn("Could not tell whether repository " + repoName + " exists: HTTP "
						+ response.getStatus() + "; kept as is");
			}
		} catch (UnirestException e) {
			LOG.error("Exception while testing if repository " + repoName + " exists", e);
		}
		return active;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public boolean listRepositories(Consumer<List<ScmRepository>> pageConsumer) {
		return repositories.list(pageConsumer);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public Optional<ScmRepository> getRepository(String repoName) {
		return repositories.getRepository(repoName);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public List<ScmBranch> listBranches(String repoName, String nameFilter, int limit) {
		return repositories.listBranches(repoName, nameFilter, limit);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public Optional<ScmBranch> getBranch(String repoName, String branchName) {
		return repositories.getBranch(repoName, branchName);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public String getFileContentAtCommit(String repoName, String commitHash, String filePath) {
		return repositories.getFileContent(repoName, commitHash, filePath);
	}

	@Override
	public com.tracelink.appsec.watchtower.core.scan.code.scm.api.FileFetch fetchFileAtCommit(
			String repoName, String commitHash, String filePath) {
		return repositories.fetchFile(repoName, commitHash, filePath);
	}

	/**
	 * create a simple URL path from a base and path elements
	 *
	 * @param base         the base URL (hostname, port, and/or path elements)
	 * @param pathElements additional path elements to add
	 * @return the concatenated string of base + path elements
	 */
	private String buildRequestUrl(String base, String... pathElements) {
		StringBuilder sb = new StringBuilder(base);
		for (String elem : pathElements) {
			sb.append("/").append(elem);
		}
		return sb.toString();
	}

	/**
	 * Shortcut to make a GET request to the provided url with the provided params
	 *
	 * @param url    the url of the target resource
	 * @param params any parameters to add to the request, may be null
	 * @return the response from the target url
	 */
	private GetRequest makeGetRequest(String url, Map<String, Object> params) {
		return Unirest.get(url).basicAuth(apiEntity.getUser(), apiEntity.getAuth())
				.header("accept", "application/json").queryString(params);
	}

	/**
	 * Shortcut to make a POST request to the provided url with the provided params
	 *
	 * @param url    the url of the target resource
	 * @param params any parameters to add to the request, may be null
	 * @return the response from the target url
	 */
	private HttpRequestWithBody makePostRequest(String url, Map<String, Object> params) {
		return Unirest.post(url).basicAuth(apiEntity.getUser(), apiEntity.getAuth())
				.header("accept", "application/json").queryString(params);
	}

	/**
	 * Shortcut to make a PUT request to the provided url with the provided params
	 *
	 * @param url    the url of the target resource
	 * @param params any parameters to add to the request, may be null
	 * @return the response from the target url
	 */
	private HttpRequestWithBody makePutRequest(String url, Map<String, Object> params) {
		return Unirest.put(url).basicAuth(apiEntity.getUser(), apiEntity.getAuth())
				.header("accept", "application/json").queryString(params);
	}

	/**
	 * Shortcut to make a DELETE request to the provided url with the provided params
	 *
	 * @param url    the url of the target resource
	 * @param params any parameters to add to the request, may be null
	 * @return the response from the target url
	 */
	private HttpRequestWithBody makeDeleteRequest(String url, Map<String, Object> params) {
		return Unirest.delete(url).basicAuth(apiEntity.getUser(), apiEntity.getAuth())
				.header("accept", "application/json").queryString(params);
	}

	/**
	 * Bitbucket has a rate limiter that will reject certain requests over a limit. This handles
	 * waiting the timeout period given in a retry header.
	 *
	 * @param headers the response headers
	 * @param retries the number of retries left to make
	 * @throws UnirestException if the retries have expired
	 */
	/**
	 * Parses Bitbucket's {@code Retry-After} header as whole seconds, per HTTP's
	 * definition of the header - distinct from {@link #handleRateLimiter}'s own
	 * parsing, which historically treats the value as milliseconds for its blocking
	 * {@code Thread.sleep()}. Not unifying the two: this is a pre-existing discrepancy
	 * worth its own look, not something to fix silently as a side effect of item 4.7.
	 *
	 * @param headers the response headers from a 429 response
	 * @return the delay in seconds, defaulting to 1 if the header is missing or
	 *         unparsable
	 */
	private static int parseRetryAfterSeconds(Headers headers) {
		try {
			int seconds = Integer.parseInt(headers.getFirst("Retry-After"));
			return Math.max(seconds, 1);
		} catch (NumberFormatException e) {
			return 1;
		}
	}

	/**
	 * Makes a call, repeating it while Bitbucket answers 429, up to the shared retry budget.
	 *
	 * @param call the request to make
	 * @param <T>  the response body type
	 * @return the first response that is not a 429
	 * @throws UnirestException if the retries run out
	 */
	static <T> HttpResponse<T> withRetry(Supplier<HttpResponse<T>> call) {
		HttpResponse<T> response = call.get();
		int retries = MAX_RATE_LIMIT_RETRIES;
		while (response.getStatus() == 429) {
			handleRateLimiter(response.getHeaders(), retries--);
			response = call.get();
		}
		return response;
	}

	static void handleRateLimiter(Headers headers, int retries) throws UnirestException {
		if (retries == 0) {
			throw new UnirestException("RateLimiter limits reached. Abandoning Request");
		}

		int retryPeriod;
		try {
			retryPeriod = Integer.parseInt(headers.getFirst("Retry-After"));
			if (retryPeriod > 10000) {
				retryPeriod = 1000;
			}
		} catch (NumberFormatException e) {
			retryPeriod = 1000;
		}

		LOG.error("Bitbucket Rate Limiting hit. Backing off for " + retryPeriod + " ms");

		try {
			Thread.sleep(retryPeriod);
		} catch (InterruptedException e) {
			LOG.error("Exception while sleeping during Bitbucket API retry", e);
		}
	}

}
