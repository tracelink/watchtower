package com.tracelink.appsec.watchtower.core.scan.code.scm.api.bb;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import jakarta.persistence.Column;
import jakarta.persistence.Convert;
import jakarta.persistence.Entity;
import jakarta.persistence.Table;

import org.apache.commons.lang3.StringUtils;
import org.springframework.web.util.UriUtils;

import com.tracelink.appsec.watchtower.core.encryption.converter.StringEncryptedAttributeConverter;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.ApiIntegrationException;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.ApiType;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.RegisterState;
import com.tracelink.appsec.watchtower.core.scan.code.scm.api.AbstractScmIntegrationEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.api.IScmApi;
import com.tracelink.appsec.watchtower.core.scan.code.scm.api.bb.BBCloudRejectOption.BBCloudRejectOptionConverter;

/**
 * Entity for the Bitbucket Cloud Integration API
 *
 * @author csmith
 */
@Entity
@Table(name = "bb_cloud_integration_entity")
public class BBCloudIntegrationEntity extends AbstractScmIntegrationEntity {

	@Column(name = "workspace")
	private String workspace;

	@Column(name = "username")
	private String user;

	@Column(name = "authentication")
	@Convert(converter = StringEncryptedAttributeConverter.class)
	private String auth;

	/**
	 * Shared secret for verifying workspace and repository webhook signatures. Encrypted at rest.
	 * Incoming deliveries fail closed when it is blank; removing a workspace hook retains it.
	 */
	@Column(name = "webhook_secret")
	@Convert(converter = StringEncryptedAttributeConverter.class)
	private String webhookSecret;

	@Column(name = "previous_webhook_secret")
	@Convert(converter = StringEncryptedAttributeConverter.class)
	private String previousWebhookSecret;
	@Column(name = "previous_webhook_secret_until")
	private Long previousWebhookSecretUntil;
	public String getPreviousWebhookSecret() { return previousWebhookSecret; }
	public Long getPreviousWebhookSecretUntil() { return previousWebhookSecretUntil; }
	public void setPreviousWebhookSecret(String secret) { previousWebhookSecret = secret; }
	public void setPreviousWebhookSecretUntil(Long until) { previousWebhookSecretUntil = until; }

	@Column(name = "reject_option")
	@Convert(converter = BBCloudRejectOptionConverter.class)
	private BBCloudRejectOption rejectOption;

	/**
	 * The Bitbucket-assigned id of the webhook this integration registered, captured on
	 * registration so a later unregister or re-register targets the same hook instead of
	 * creating a duplicate. Blank until a registration succeeds.
	 */
	@Column(name = "webhook_uuid")
	private String webhookUuid;

	@jakarta.persistence.Transient private Long cachedWebhookRepositories;
	@jakarta.persistence.Transient private Boolean cachedWorkspaceActive;
	public Long getCachedWebhookRepositories(){return cachedWebhookRepositories;}
	public void setCachedWebhookRepositories(Long count){cachedWebhookRepositories=count;}
	public Boolean getCachedWorkspaceActive(){return cachedWorkspaceActive;}
	public void setCachedWorkspaceActive(Boolean active){cachedWorkspaceActive=active;}

	public BBCloudIntegrationEntity() {
		// Bitbucket Cloud supports self-registration (unlike some future integration type
		// that might not), so a freshly created entity should offer the Register button
		// rather than starting in the base class's NOT_SUPPORTED default.
		setRegisterState(RegisterState.NOT_REGISTERED);
	}

	public String getWebhookUuid() {
		return webhookUuid;
	}

	public void setWebhookUuid(String webhookUuid) {
		this.webhookUuid = webhookUuid;
	}

	public String getWebhookSecret() {
		return webhookSecret;
	}

	public void setWebhookSecret(String webhookSecret) {
		this.webhookSecret = webhookSecret;
	}

	/**
	 * Whether this integration requires incoming webhooks to be signed.
	 *
	 * @return true if a shared secret has been configured
	 */
	public boolean requiresSignedWebhooks() {
		return StringUtils.isNotBlank(webhookSecret);
	}

	/**
	 * Verifies a webhook delivery against this integration's shared secret.
	 * <p>
	 * Lives here rather than in the REST layer so the Bitbucket signature scheme stays
	 * with the Bitbucket integration. The controller only decides what to do with the
	 * answer.
	 *
	 * @param rawBody         the request body bytes exactly as received
	 * @param signatureHeader the {@value BBWebhookSignature#HEADER_NAME} value
	 * @return true if the delivery is correctly signed for this integration
	 */
	public boolean isWebhookSignatureValid(byte[] rawBody, String signatureHeader) {
		boolean current = BBWebhookSignature.isValid(webhookSecret, rawBody, signatureHeader);
		boolean previous = previousWebhookSecretUntil != null
				&& previousWebhookSecretUntil > System.currentTimeMillis()
				&& BBWebhookSignature.isValid(previousWebhookSecret, rawBody, signatureHeader);
		return current | previous;
	}

	public String getWorkspace() {
		return workspace;
	}

	public void setWorkspace(String workspace) {
		this.workspace = workspace;
	}

	public String getApiBase() {
		return "https://api.bitbucket.org/2.0";
	}

	/**
	 * Make the workspace url for the Bitbucket cloud API
	 *
	 * @return the api workspace url
	 */
	public String makeApiWorkspaceUrl() {
		return String.format("%s/repositories/%s", getApiBase(), getWorkspace());
	}

	/**
	 * Make the repository url for the Bitbucket cloud API
	 *
	 * @param repositoryName the repository to use
	 * @return the api repository url
	 */
	public String makeApiRepoUrl(String repositoryName) {
		return String.format("%s/repositories/%s/%s", getApiBase(), getWorkspace(),
				repositoryName);
	}

	/**
	 * Make the pull request url for the Bitbucket cloud API
	 *
	 * @param repositoryName the repository to use
	 * @param pullRequestId  the pull request to use
	 * @return the api pull request url
	 */
	public String makeApiPRUrl(String repositoryName, String pullRequestId) {
		return String.format("%s/pullrequests/%s", makeApiRepoUrl(repositoryName), pullRequestId);
	}

	/**
	 * Make the url to fetch a single file's content at a given commit, for the Bitbucket cloud
	 * API.
	 *
	 * @param repositoryName the repository to use
	 * @param commitHash     the commit to fetch the file's content at
	 * @param filePath       the path, relative to the repository root, of the file to fetch
	 * @return the api source file url
	 */
	public String makeSourceFileUrl(String repositoryName, String commitHash, String filePath) {
		return String.format("%s/src/%s/%s", makeApiRepoUrl(repositoryName), commitHash,
				filePath);
	}

	/**
	 * Make the url to list every file in the repository tree at a given commit, for the
	 * Bitbucket cloud API.
	 *
	 * @param repositoryName the repository to use
	 * @param commitHash     the commit to list the file tree at
	 * @return the api source listing url
	 */
	public String makeSourceListingUrl(String repositoryName, String commitHash) {
		return String.format("%s/src/%s/", makeApiRepoUrl(repositoryName), commitHash);
	}

	/**
	 * Make the url for listing and creating workspace-level webhooks for the Bitbucket cloud
	 * API. A workspace-level hook covers every repository in the workspace, so a single
	 * registration is enough (see IMPROVEMENT_PLAN.md item 8).
	 *
	 * @return the api workspace hooks url
	 */
	public String makeWorkspaceHooksUrl() {
		return String.format("%s/workspaces/%s/hooks", getApiBase(), getWorkspace());
	}

	/** Repository slugs are path segments, never caller-supplied paths or query strings. */
	public String makeRepoHooksUrl(String slug) {
		if (slug == null || (!slug.matches("[A-Za-z0-9_.-]{1,255}") || slug.equals(".") || slug.equals(".."))) {
			throw new IllegalArgumentException("Invalid Bitbucket repository slug");
		}
		return makeApiRepoUrl(slug) + "/hooks";
	}

	public String getUser() {
		return user;
	}

	public void setUser(String user) {
		this.user = user;
	}

	public String getAuth() {
		return auth;
	}

	public void setAuth(String auth) {
		this.auth = auth;
	}

	public BBCloudRejectOption getRejectOption() {
		return rejectOption;
	}

	public void setRejectOption(BBCloudRejectOption rejectOption) {
		this.rejectOption = rejectOption;
	}

	@Override
	public void configureEntityFromParameters(Map<String, String> parameters)
			throws ApiIntegrationException {
		List<String> neededParams =
				new ArrayList<>(
						Arrays.asList("apiLabel", "workspace", "user", "auth", "rejectOption"));
		parameters.entrySet().removeIf(e -> StringUtils.isBlank(e.getValue()));
		neededParams.removeAll(parameters.keySet());

		if (!neededParams.isEmpty()) {
			throw new ApiIntegrationException("Missing value for "
					+ neededParams.stream().collect(Collectors.joining(", ")));
		}
		setApiLabel(parameters.get("apiLabel"));
		setWorkspace(parameters.get("workspace"));
		setUser(parameters.get("user"));
		setAuth(parameters.get("auth"));
		setRejectOption(BBCloudRejectOption.fromString(parameters.get("rejectOption")));
		// Optional when saving settings. Until a secret is configured or registration
		// generates one, incoming webhook deliveries are rejected.
		setWebhookSecret(parameters.get("webhookSecret"));
	}

	@Override
	public void preserveConfiguredSecrets(Map<String, String> parameters) {
		if (StringUtils.isBlank(parameters.get("auth")) && StringUtils.isNotBlank(auth)) {
			parameters.put("auth", auth);
		}
		if (StringUtils.isBlank(parameters.get("webhookSecret"))
				&& StringUtils.isNotBlank(webhookSecret)) {
			parameters.put("webhookSecret", webhookSecret);
		}
	}

	/**
	 * Create a url pointing to the bitbucket cloud pull request
	 * 
	 * @param repository    the repository of the pull request
	 * @param pullRequestId the id of the pull request
	 * @return a url link for this pull request
	 */
	public String makePRLink(String repository, String pullRequestId) {
		return String.format("https://bitbucket.org/%s/%s/pull-requests/%s", getWorkspace(),
				repository, pullRequestId);
	}

	@Override
	public String makeFileLink(String repository, String commitHash, String filePath,
			int line) {
		String link = String.format("https://bitbucket.org/%s/%s/src/%s/%s", getWorkspace(),
				repository, commitHash,
				UriUtils.encodePath(filePath, StandardCharsets.UTF_8));
		return line > 0 ? link + "#lines-" + line : link;
	}

	/**
	 * Create a link to download the zip source of a repo at a commit
	 *
	 * @param repository the repository of the code
	 * @param commitId   the commit hash to download at
	 * @return a download link
	 */
	public String makeDownloadLink(String repository, String commitId) {
		return String.format("https://bitbucket.org/%s/%s/get/%s.zip", getWorkspace(), repository,
				commitId);
	}

	@Override
	public ApiType getApiType() {
		return ApiType.BITBUCKET_CLOUD;
	}

	@Override
	public IScmApi createApi() {
		return new BBCloudApi(this);
	}
}
