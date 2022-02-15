package com.tracelink.appsec.watchtower.core.scan.scm.bb;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;

import com.jayway.jsonpath.JsonPath;
import com.tracelink.appsec.watchtower.core.exception.ScanRejectedException;
import com.tracelink.appsec.watchtower.core.scan.scm.IScmApi;
import com.tracelink.appsec.watchtower.core.scan.scm.apiintegration.ApiIntegrationException;
import com.tracelink.appsec.watchtower.core.scan.scm.pr.PullRequest;
import com.tracelink.appsec.watchtower.core.scan.scm.pr.data.DiffFile;

import kong.unirest.GetRequest;
import kong.unirest.Headers;
import kong.unirest.HttpRequestWithBody;
import kong.unirest.HttpResponse;
import kong.unirest.JsonNode;
import kong.unirest.Unirest;
import kong.unirest.UnirestException;
import kong.unirest.json.JSONArray;
import kong.unirest.json.JSONObject;
import net.lingala.zip4j.ZipFile;

/**
 * An implementation of the {@linkplain IScmApi} for Bitbucket Cloud
 * 
 * @author csmith
 *
 */
public class BBCloudApi implements IScmApi {
	private static Logger LOG = LoggerFactory.getLogger(BBCloudApi.class);

	private BBCloudIntegrationEntity apiEntity;

	public BBCloudApi(BBCloudIntegrationEntity apiEntity) {
		this.apiEntity = apiEntity;
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
				LOG.debug(response.getBody());
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
		Path tempFile = Files.createTempFile(null, ".zip");
		String url = apiEntity.makeDownloadLink(pullRequest.getRepoName(),
				pullRequest.getCommitHash().substring(0, 7));
		try (FileOutputStream fw = new FileOutputStream(tempFile.toFile())) {
			AtomicReference<IOException> e = new AtomicReference<>(null);
			int retries = 5;
			do {
				makeGetRequest(url, null)
						.thenConsume(r -> {
							try {
								if (r.getStatus() != 200) {
									throw new IOException("Response code is " + r.getStatus());
								}
								IOUtils.copyLarge(r.getContent(), fw);
							} catch (IOException ex) {
								e.set(ex);
							}
						});
				if (e.get() != null) {
					LOG.error("Bad response during download: " + e.get().getMessage());
					throw e.get();
				}
				retries--;
			} while (retries > 0 && e.get() == null);
		}
		Path tempDir = Files.createTempDirectory(null);
		unzip(tempFile.toFile(), tempDir);
		FileUtils.deleteQuietly(targetDirectory.toFile());
		Files.list(tempDir).findFirst().get().toFile().renameTo(targetDirectory.toFile());

		FileUtils.deleteQuietly(tempDir.toFile());
		FileUtils.deleteQuietly(tempFile.toFile());
	}

	private void unzip(File zipFile, Path targetDir) throws IOException {
		ZipFile zip = new ZipFile(zipFile);
		zip.extractAll(targetDir.toAbsolutePath().toString());
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
		params.put("context", "100000");
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
		bbpr.setSubmitTime(pullRequest.getSubmitTime());
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
			} else {
				LOG.error("Bad response: " + response.getStatus()
						+ " while getting more Pull Request information for PR "
						+ pullRequest.getPRString());
				LOG.debug(response.getBody());
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
	public void sendComment(PullRequest pullRequest, String comment) {
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
				LOG.debug(response.getBody());
			}
		} catch (UnirestException e) {
			LOG.error("Exception while sending report for PR " + pullRequest.getPRString(), e);
		}
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void blockPR(PullRequest pullRequest) {
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
				LOG.debug(response.getBody());
			}
		} catch (UnirestException e) {
			LOG.error("Exception while declining PR " + pullRequest.getPRString(), e);
		}
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
					LOG.debug(response.getBody().toString());
					break;
				}
				JSONObject body = response.getBody().getObject();
				JSONArray values = body.getJSONArray("values");
				for (int i = 0; i < values.length(); i++) {
					JSONObject value = values.getJSONObject(i);
					BBPullRequest bbpr = new BBPullRequest(apiEntity.getApiLabel());
					bbpr.setRepoName(repoName);
					bbpr.setSubmitTime(System.currentTimeMillis());
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

			active = response.getStatus() == 200;
		} catch (UnirestException e) {
			LOG.error("Exception while testing if repository " + repoName + " exists", e);
		}
		return active;
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
	 * Bitbucket has a rate limiter that will reject certain requests over a limit. This handles
	 * waiting the timeout period given in a retry header.
	 * 
	 * @param headers the response headers
	 * @param retries the number of retries left to make
	 * @throws UnirestException if the retries have expired
	 */
	private void handleRateLimiter(Headers headers, int retries) throws UnirestException {
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
