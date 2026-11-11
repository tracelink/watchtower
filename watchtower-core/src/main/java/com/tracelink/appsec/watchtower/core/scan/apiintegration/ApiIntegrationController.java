package com.tracelink.appsec.watchtower.core.scan.apiintegration;

import java.nio.charset.StandardCharsets;
import java.security.Principal;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataAccessException;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;
import org.springframework.web.util.UriUtils;

import com.tracelink.appsec.watchtower.core.auth.model.CorePrivilege;
import com.tracelink.appsec.watchtower.core.mvc.WatchtowerModelAndView;
import com.tracelink.appsec.watchtower.core.mvc.PagedResult;
import com.tracelink.appsec.watchtower.core.scan.IWatchtowerApi;
import com.tracelink.appsec.watchtower.core.scan.repository.RepositoryInventoryService;
import com.tracelink.appsec.watchtower.core.scan.repository.RepositoryService;
import com.tracelink.appsec.watchtower.core.scan.repository.RepositoryStatusService;

/**
 * Controller for all apisettings which stores and handles modifying setting to connect to external
 * SCMs
 *
 * @author csmith, mcool
 */
@Controller
@RequestMapping("/apisettings")
@PreAuthorize("hasAuthority('" + CorePrivilege.API_SETTINGS_VIEW_NAME + "')")
public class ApiIntegrationController {

	private static final Logger LOG = LoggerFactory.getLogger(ApiIntegrationController.class);

	private static final String SECRET_FIELD_SCRIPT = "/scripts/secret-field.js";

	/** Where Test connection returns to: the integration's own page, when pressed there. */
	private static final String RETURN_TO_INTEGRATION = "integration";

	private final ApiIntegrationService apiService;

	private final IntegrationHealthService health;

	private final RepositoryService repositories;

	private final RepositoryStatusService repositoryStatuses;

	private final RepositoryInventoryService inventory;

	public ApiIntegrationController(@Autowired ApiIntegrationService apiService,
			IntegrationHealthService health, RepositoryService repositories,
			RepositoryStatusService repositoryStatuses, RepositoryInventoryService inventory) {
		this.apiService = apiService;
		this.health = health;
		this.repositories = repositories;
		this.repositoryStatuses = repositoryStatuses;
		this.inventory = inventory;
	}

	@Autowired
	private com.tracelink.appsec.watchtower.core.scan.apiintegration.webhook.BBWebhookManagementService webhookManagement;

	@GetMapping("")
	public WatchtowerModelAndView apiSettings(@RequestParam(defaultValue = "0") int page) {
		WatchtowerModelAndView mav = new WatchtowerModelAndView("configuration/apisettings");
		if (page < 0) {
			mav.setViewName("redirect:/apisettings?page=0");
			return mav;
		}

		List<String> types =
				Stream.of(ApiType.values()).map(ApiType::getTypeName).collect(Collectors.toList());

		mav.addObject("apiTypeNames", types);
		PageRequest pageable = PageRequest.of(page, 10, Sort.by("apiLabel"));
		Page<ApiIntegrationEntity> settings = apiService.getSettings(pageable);
		if (settings == null) {
			List<ApiIntegrationEntity> allSettings = apiService.getAllSettings();
			settings = new PageImpl<>(allSettings, pageable, allSettings.size());
		}
		PagedResult<ApiIntegrationEntity> pagination = PagedResult.of(settings, setting -> setting);
		if (pagination.totalPages() > 0 && page >= pagination.totalPages()) {
			mav.setViewName("redirect:/apisettings?page=" + (pagination.totalPages() - 1));
			return mav;
		}
		webhookManagement.decorate(pagination.content());
		mav.addObject("apiSettings", pagination.content());
		mav.addObject("failing", pagination.content().stream().filter(health::isFailing)
				.map(ApiIntegrationEntity::getApiLabel).collect(Collectors.toSet()));
		mav.addObject("repositoryCounts", repositories.countsByIntegration());
		mav.addObject("onlyRepositories", repositories.onlyRepositoryByIntegration());
		mav.addObject("hasApiSettings", !pagination.content().isEmpty());
		mav.addObject("pagination", pagination);
		mav.addScriptReference("/scripts/modal-delete-api.js");
		return mav;
	}

	@GetMapping("/{label}/webhooks/manage")
	public WatchtowerModelAndView webhooks(@PathVariable String label, RedirectAttributes redirectAttributes) {
		ApiIntegrationEntity entity = apiService.findByLabel(label);
		if (entity == null || entity.getApiType() != ApiType.BITBUCKET_CLOUD) {
			redirectAttributes.addFlashAttribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,
					"Bitbucket integration not found");
			WatchtowerModelAndView redirect = new WatchtowerModelAndView("configuration/bitbucketwebhooks");
			redirect.setViewName("redirect:/apisettings");
			return redirect;
		}
		WatchtowerModelAndView mav = new WatchtowerModelAndView("configuration/bitbucketwebhooks");
		mav.addObject("apiLabel", entity.getApiLabel());
		mav.addScriptReference("/scripts/bitbucket-webhooks.js");
		return mav;
	}

	@GetMapping("/create")
	@PreAuthorize("hasAuthority('" + CorePrivilege.API_SETTINGS_MODIFY_NAME + "')")
	public WatchtowerModelAndView createApi(@RequestParam String apiType,
			RedirectAttributes redirectAttributes) {
		WatchtowerModelAndView mav = new WatchtowerModelAndView("configuration/apiconfigure");
		ApiType type = ApiType.typeForName(apiType);
		if (type == null) {
			redirectAttributes.addFlashAttribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,
					"Unknown API");
			mav.setViewName("redirect:/apisettings");
			return mav;
		}
		mav.addObject("apiType", type);
		mav.addObject("template", type.getTemplate());
		mav.addScriptReference(SECRET_FIELD_SCRIPT);
		return mav;
	}

	@GetMapping("/configure")
	@PreAuthorize("hasAuthority('" + CorePrivilege.API_SETTINGS_MODIFY_NAME + "')")
	public WatchtowerModelAndView editApi(@RequestParam String apiLabel,
			RedirectAttributes redirectAttributes) {
		WatchtowerModelAndView mav = new WatchtowerModelAndView("configuration/apiconfigure");
		ApiIntegrationEntity entity = apiService.findByLabel(apiLabel);
		if (entity == null) {
			redirectAttributes.addFlashAttribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,
					"Unknown API Label");
			mav.setViewName("redirect:/apisettings");
			return mav;
		}

		webhookManagement.decorate(List.of(entity));
		mav.addObject("entity", entity);
		mav.addObject("failing", health.isFailing(entity));
		mav.addObject("apiType", entity.getApiType());
		mav.addObject("template", entity.getApiType().getTemplate());
		// For the delete confirm: how many repositories use it, and the name when there is one.
		mav.addObject("repositoryCount", repositories.countsByIntegration().getOrDefault(apiLabel, 0L));
		mav.addObject("onlyRepository", repositories.onlyRepositoryByIntegration().get(apiLabel));
		mav.addScriptReference(SECRET_FIELD_SCRIPT);
		mav.addScriptReference("/scripts/modal-delete-api.js");
		return mav;
	}

	/**
	 * Deletes an integration, and with {@code deleteRepositories} its repositories and their
	 * repository scans too; otherwise they stay as orphaned rows the inventory can clean up.
	 */
	@PostMapping("/delete")
	@PreAuthorize("hasAuthority('" + CorePrivilege.API_SETTINGS_MODIFY_NAME + "')")
	public String deleteSetting(@RequestParam String apiLabel,
			@RequestParam(defaultValue = "false") boolean deleteRepositories,
			@RequestParam(required = false) String confirmName, Principal user,
			RedirectAttributes redirectAttributes) {
		// The confirm dialog enables Delete only once the name is typed; check it here too.
		if (confirmName == null || !confirmName.trim().equals(apiLabel)) {
			redirectAttributes.addFlashAttribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,
					"Type the integration's name to delete it.");
			return "redirect:/apisettings";
		}
		try {
			apiService.delete(apiLabel);
			repositoryStatuses.forgetIntegrations();
			if (deleteRepositories) {
				int deleted = inventory.deleteAllOf(apiLabel, user.getName()).deleted();
				redirectAttributes.addFlashAttribute(WatchtowerModelAndView.SUCCESS_NOTIFICATION,
						"Deleted " + apiLabel + " and " + deleted
								+ (deleted == 1 ? " repository" : " repositories"));
			}
		} catch (ApiIntegrationException | IllegalStateException e) {
			redirectAttributes.addFlashAttribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,
					e.getMessage());
		} catch (DataAccessException e) {
			LOG.error("Deleted integration {} but not all of its repositories", apiLabel, e);
			redirectAttributes.addFlashAttribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,
					"Deleted " + apiLabel + ", but not all of its repositories; delete the rest"
							+ " from the repository list");
		}
		return "redirect:/apisettings";
	}

	@PostMapping("/update")
	@PreAuthorize("hasAuthority('" + CorePrivilege.API_SETTINGS_MODIFY_NAME + "')")
	public String updateSetting(@RequestParam String apiType, @RequestParam Optional<Long> apiId,
			@RequestParam Map<String, String> parameters, RedirectAttributes redirectAttributes) {
		ApiType api = ApiType.typeForName(apiType);
		if (api == null) {
			redirectAttributes.addFlashAttribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,
					"Unknown API");
			return "redirect:/apisettings";
		}
		try {
			if (apiId.isPresent()) {
				ApiIntegrationEntity existing = apiService.findByLabel(parameters.get("apiLabel"));
				if (existing == null || existing.getIntegrationId() != apiId.get()) {
					throw new ApiIntegrationException("Unknown API Label");
				}
				existing.preserveConfiguredSecrets(parameters);
			}
			ApiIntegrationEntity incomingEntity = api.createApiIntegrationEntity();
			incomingEntity.configureEntityFromParameters(parameters);
			apiId.ifPresent(incomingEntity::setIntegrationId);
			apiService.upsertEntity(incomingEntity);
			repositoryStatuses.forgetIntegrations();
			redirectAttributes.addFlashAttribute(WatchtowerModelAndView.SUCCESS_NOTIFICATION,
					"Successfully updated " + incomingEntity.getApiLabel());
		} catch (IllegalArgumentException | IllegalStateException | ApiIntegrationException e) {
			redirectAttributes.addFlashAttribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,
					e.getMessage());
		}
		return "redirect:/apisettings";
	}

	@PostMapping("/testConnection")
	public String testConnection(@RequestParam String apiLabel,
			@RequestParam(required = false) String returnTo, RedirectAttributes redirectAttributes) {
		ApiIntegrationEntity entity = apiService.findByLabel(apiLabel);
		if (entity == null) {
			redirectAttributes.addFlashAttribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,
					"Unknown API Label");
			return "redirect:/apisettings";
		}
		String back = RETURN_TO_INTEGRATION.equals(returnTo)
				? "redirect:/apisettings/configure?apiLabel="
						+ UriUtils.encodeQueryParam(apiLabel, StandardCharsets.UTF_8)
				: "redirect:/apisettings";
		try {
			IWatchtowerApi api = entity.createApi();
			api.testClientConnection();
			health.record(apiLabel, true, null);
			redirectAttributes.addFlashAttribute(WatchtowerModelAndView.SUCCESS_NOTIFICATION,
					"Success");
			addConnectionResult(redirectAttributes, apiLabel, "success",
					"Connection succeeded");
		} catch (ApiIntegrationException e) {
			health.record(apiLabel, false, e.getMessage());
			redirectAttributes.addFlashAttribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,
					e.getMessage());
			addConnectionResult(redirectAttributes, apiLabel, "error", e.getMessage());
		} catch (IllegalStateException | NullPointerException e) {
			// Watchtower's own fault, not the provider's: say so instead of blaming the provider
			LOG.warn("Connection test of {} couldn't run", apiLabel, e);
			health.record(apiLabel, false, IntegrationPresentation.COULD_NOT_RUN + e.getMessage());
			redirectAttributes.addFlashAttribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,
					"The check couldn't run because of a Watchtower error");
			addConnectionResult(redirectAttributes, apiLabel, "error",
					"The check couldn't run because of a Watchtower error");
		} catch (RuntimeException e) {
			LOG.warn("Connection test of {} failed", apiLabel, e);
			health.record(apiLabel, false, e.getMessage());
			redirectAttributes.addFlashAttribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,
					"The connection test failed");
			addConnectionResult(redirectAttributes, apiLabel, "error",
					"The connection test failed");
		}
		return back;
	}

	private void addConnectionResult(RedirectAttributes redirectAttributes, String apiLabel,
			String tone, String message) {
		redirectAttributes.addFlashAttribute("connectionCheckLabel", apiLabel);
		redirectAttributes.addFlashAttribute("connectionCheckTone", tone);
		redirectAttributes.addFlashAttribute("connectionCheckMessage", message);
		redirectAttributes.addFlashAttribute("connectionCheckTime", Instant.now().toString());
	}

	@PostMapping("/register")
	@PreAuthorize("hasAuthority('" + CorePrivilege.API_SETTINGS_MODIFY_NAME + "')")
	public String register(@RequestParam String apiLabel, RedirectAttributes redirectAttributes) {
		try {
			apiService.register(apiLabel);
			redirectAttributes.addFlashAttribute(WatchtowerModelAndView.SUCCESS_NOTIFICATION,
					"Started registration");
		} catch (ApiIntegrationException | IllegalStateException e) {
			redirectAttributes.addFlashAttribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,
					e.getMessage());
		}
		return "redirect:/apisettings";
	}

	@PostMapping("/unregister")
	@PreAuthorize("hasAuthority('" + CorePrivilege.API_SETTINGS_MODIFY_NAME + "')")
	public String unregister(@RequestParam String apiLabel, RedirectAttributes redirectAttributes) {
		try {
			apiService.unregister(apiLabel);
			redirectAttributes.addFlashAttribute(WatchtowerModelAndView.SUCCESS_NOTIFICATION,
					"Started registration removal");
		} catch (ApiIntegrationException | IllegalStateException e) {
			redirectAttributes.addFlashAttribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,
					e.getMessage());
		}
		return "redirect:/apisettings";
	}
}
