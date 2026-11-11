package com.tracelink.appsec.watchtower.core.scan.apiintegration;

import java.util.List;

import org.apache.commons.lang3.StringUtils;

import com.tracelink.appsec.watchtower.core.scan.code.scm.api.bb.BBCloudRejectOption;
import com.tracelink.appsec.watchtower.core.scan.image.api.ecr.EcrRejectOption;

/**
 * How an integration reads on the Integrations pages: its provider icon, and its connection and
 * webhook states as chips with their meaning on hover. Plain words only; internal state names
 * ("Not Registered") and errors that are Watchtower's own never show as the provider's fault.
 *
 * @author Watchtower
 */
public final class IntegrationPresentation {

	/** Marks a recorded check that Watchtower itself could not run (not a provider failure). */
	static final String COULD_NOT_RUN = "Watchtower couldn't run the check: ";

	/**
	 * Errors recorded before the ECR check stopped depending on a web request (UAT walkthrough
	 * 2026-10-16): they say nothing about the provider either.
	 */
	private static final String REQUEST_CONTEXT_ERROR = "ServletRequestAttributes";

	/**
	 * One chip.
	 *
	 * @param label     the chip's text
	 * @param tone      success, warning, danger or neutral
	 * @param icon      a Material icon name
	 * @param tip       the hover text; a time, when {@code tipMillis} is set, follows it
	 * @param tipMillis the check time shown in the hover text, or null
	 */
	public record Chip(String label, String tone, String icon, String tip, Long tipMillis) {
	}

	/**
	 * One choice of what happens when a scan blocks a pull request or an image.
	 *
	 * @param value the stored option name, posted as {@code rejectOption}
	 * @param label the plain words shown on the chip
	 * @param icon  a Material icon name
	 * @param tip   what the choice does
	 */
	public record Choice(String value, String label, String icon, String tip) {
	}

	private static final List<Choice> BITBUCKET_CHOICES = List.of(
			new Choice(BBCloudRejectOption.DO_NOTHING.getName(), "Do nothing", "do_not_disturb_on",
					"Watchtower records the result only."),
			new Choice(BBCloudRejectOption.SEND_COMMENT.getName(), "Comment", "comment",
					"Watchtower comments the findings on the pull request."),
			new Choice(BBCloudRejectOption.BLOCK_PR.getName(), "Comment and block", "block",
					"Watchtower comments and declines the pull request."),
			new Choice(BBCloudRejectOption.APPROVE_OR_REQUEST_CHANGES.getName(),
					"Comment and approve or request changes", "rate_review",
					"Watchtower comments, then approves a pull request without new blocking findings"
							+ " or requests changes on one with them. For a Watchtower account set as"
							+ " a default reviewer with a merge check requiring its approval."));

	private static final List<Choice> ECR_CHOICES = List.of(
			new Choice(EcrRejectOption.DO_NOTHING.getName(), "Do nothing", "do_not_disturb_on",
					"Watchtower records the result only."),
			new Choice(EcrRejectOption.DELETE_IMAGE.getName(), "Delete the image", "delete",
					"Watchtower deletes an image with blocking findings. This can't be undone."));

	private IntegrationPresentation() {
	}

	/**
	 * @return the choices of what happens when a scan blocks a pull request (Bitbucket) or an
	 *         image (ECR)
	 */
	public static List<Choice> blockChoices(ApiType type) {
		return type == ApiType.ECR ? ECR_CHOICES : BITBUCKET_CHOICES;
	}

	/**
	 * @return the provider's icon: a code repository host or an image registry
	 */
	public static String icon(ApiIntegrationEntity integration) {
		return integration.getApiType() == ApiType.ECR ? "inventory_2" : "code";
	}

	/**
	 * The last connection check as a chip.
	 *
	 * @param integration the integration
	 * @param failing     whether {@link IntegrationHealthService#isFailing} holds
	 * @return the chip
	 */
	public static Chip connection(ApiIntegrationEntity integration, boolean failing) {
		Long checkedAt = integration.getHealthCheckedAt();
		if (checkedAt == null || integration.getHealthOk() == null) {
			return new Chip("Not checked", "neutral", "help_outline",
					"No connection check has run yet. Test checks it now.", null);
		}
		if (Boolean.TRUE.equals(integration.getHealthOk())) {
			return new Chip("Connected", "success", "check_circle", "Last check passed: ",
					checkedAt);
		}
		String error = integration.getHealthError();
		if (couldNotRun(error)) {
			return new Chip("Couldn't check", "warning", "error_outline",
					"The last check couldn't run because of a Watchtower error, not the provider."
							+ " Test checks it again. Last tried: ",
					checkedAt);
		}
		// Plain words on the chip; the provider's raw error is behind Details (Fixes board).
		boolean keyRejected = isKeyRejected(error);
		String why = keyRejected
				? provider(integration) + " rejected the saved key. Replace the key on the integration page. "
				: "The connection check failed. Details has the provider's error. ";
		if (!failing) {
			return new Chip("Failed", "neutral", "error_outline",
					why + "Last check failed over a day ago: ", checkedAt);
		}
		return keyRejected
				? new Chip("Key rejected", "danger", "key_off", why + "Last check: ", checkedAt)
				: new Chip("Failing", "danger", "error", why + "Last check: ", checkedAt);
	}

	/**
	 * @return the provider's own error from the last failed check, for the Details popover, or
	 *         null when the last check passed, never ran or failed in Watchtower itself
	 */
	public static String failureDetail(ApiIntegrationEntity integration) {
		String error = integration.getHealthError();
		if (!Boolean.FALSE.equals(integration.getHealthOk()) || StringUtils.isBlank(error)
				|| couldNotRun(error)) {
			return null;
		}
		return error;
	}

	/** True for an error that means the provider refused the saved credentials (401/403). */
	static boolean isKeyRejected(String error) {
		if (error == null) {
			return false;
		}
		String lower = error.toLowerCase(java.util.Locale.ROOT);
		return lower.contains("status code: 403") || lower.contains("status code: 401")
				|| lower.contains("401 unauthorized") || lower.contains("403 forbidden")
				|| lower.contains("security token") || lower.contains("invalidclienttokenid")
				|| lower.contains("signaturedoesnotmatch") || lower.contains("bad credentials");
	}

	private static String provider(ApiIntegrationEntity integration) {
		return integration.getApiType() == ApiType.ECR ? "AWS" : "Bitbucket";
	}

	/**
	 * The webhook state as a chip, or null when the provider has no webhook to register.
	 *
	 * @param integration the integration
	 * @return the chip, or null
	 */
	public static Chip webhook(ApiIntegrationEntity integration) {
		RegisterState state = integration.getRegisterState();
		if (state == null || state == RegisterState.NOT_SUPPORTED) {
			return null;
		}
		if (integration instanceof com.tracelink.appsec.watchtower.core.scan.code.scm.api.bb.BBCloudIntegrationEntity bb
				&& (bb.getCachedWebhookRepositories()!=null || bb.getCachedWorkspaceActive()!=null)) {
			long repos=bb.getCachedWebhookRepositories()==null?0:bb.getCachedWebhookRepositories();
			boolean workspace=Boolean.TRUE.equals(bb.getCachedWorkspaceActive());
			// Never checked is not the same as checked and inactive
			boolean workspaceUnknown=bb.getCachedWorkspaceActive()==null;
			String label=workspace?(repos>0?"Workspace + "+repos+(repos==1?" repo hook":" repo hooks"):"Workspace"):(repos>0?repos+" repos":(workspaceUnknown?"Workspace hook not checked yet":"No active workspace hook"));
			String tip=workspace&&repos>0
					? "The workspace hook already covers every repository, so "+(repos==1?"1 repository also has":repos+" repositories also have")
					+" its own hook. A push is still scanned once (duplicate deliveries are de-duplicated); remove the extra hooks if they are not needed. View hooks for each hook's state, errors and checked times."
					: "Last refreshed webhook inventory. View hooks for individual active states, errors and checked times.";
			return new Chip(label,workspace&&repos>0?"warning":workspace||repos>0?"success":"neutral","webhook",tip,null);
		}
		if (integration.getApiType() == ApiType.BITBUCKET_CLOUD) {
			return switch (state) {
				case REGISTERED -> new Chip("Workspace", "success", "webhook",
						"Workspace webhook registered. View hooks checks its current state; repository coverage is not yet inventoried.", null);
				case IN_PROGRESS -> new Chip("Workspace changing", "neutral", "hourglass_top",
						"Workspace webhook registration or removal is in progress. Repository hooks are independent.", null);
				case FAILED -> new Chip("Workspace setup failed", "danger", "webhook",
						StringUtils.defaultIfBlank(integration.getRegisterError(), "Workspace webhook setup failed.")
								+ " Repository hooks are independent.", null);
				default -> new Chip("Workspace not set up", "neutral", "webhook",
						"Watchtower has not registered a workspace hook. Repository hooks may still deliver events; their coverage is not yet inventoried.", null);
			};
		}

		return switch (state) {
			case REGISTERED -> new Chip("Set up", "success", "webhook",
					"Watchtower registered the webhook, so new pull requests and images are scanned"
							+ " automatically.",
					null);
			case IN_PROGRESS -> new Chip("Setting up", "neutral", "hourglass_top",
					"Watchtower is registering the webhook.", null);
			case FAILED -> new Chip("Setup failed", "danger", "webhook",
					StringUtils.defaultIfBlank(integration.getRegisterError(),
							"Registering the webhook failed.") + " Register webhook tries again.",
					null);
			default -> new Chip("Not set up", "neutral", "webhook",
					"Watchtower has not registered the webhook itself. A webhook added by hand in"
							+ " the provider still starts scans.",
					null);
		};
	}

	/**
	 * @return true if a recorded error is Watchtower's own, so the check says nothing about the
	 *         provider
	 */
	static boolean couldNotRun(String error) {
		return error != null
				&& (error.startsWith(COULD_NOT_RUN) || error.contains(REQUEST_CONTEXT_ERROR));
	}
}
