package com.tracelink.appsec.watchtower.core.scan.apiintegration;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import com.tracelink.appsec.watchtower.core.auth.model.CorePrivilege;
import com.tracelink.appsec.watchtower.core.mvc.WatchtowerModelAndView;
import com.tracelink.appsec.watchtower.core.scan.IWatchtowerApi;

/**
 * Controller for all apisettings which stores and handles modifying setting to connect to external
 * SCMs
 *
 * @author csmith
 */
@Controller
@PreAuthorize("hasAuthority('" + CorePrivilege.API_SETTINGS_VIEW_NAME + "')")
public class APIIntegrationController {

	private APIIntegrationService apiService;


	public APIIntegrationController(@Autowired APIIntegrationService apiService) {
		this.apiService = apiService;
	}

	@GetMapping("/apisettings")
	public WatchtowerModelAndView apiSettings() {
		WatchtowerModelAndView mav = new WatchtowerModelAndView("configuration/apisettings");

		List<String> types =
				Stream.of(ApiType.values()).map(s -> s.getTypeName()).collect(Collectors.toList());

		mav.addObject("apiTypeNames", types);
		mav.addObject("apiSettings", apiService.getAllSettings());
		mav.addScriptReference("/scripts/modal-delete-api.js");
		return mav;
	}

	@GetMapping("/apisettings/create")
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
		return mav;
	}

	@GetMapping("/apisettings/configure")
	@PreAuthorize("hasAuthority('" + CorePrivilege.API_SETTINGS_MODIFY_NAME + "')")
	public WatchtowerModelAndView editApi(@RequestParam String apiLabel,
			RedirectAttributes redirectAttributes) {
		WatchtowerModelAndView mav = new WatchtowerModelAndView("configuration/apiconfigure");
		APIIntegrationEntity entity = apiService.findByLabel(apiLabel);
		if (entity == null) {
			redirectAttributes.addFlashAttribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,
					"Unknown API Label");
			mav.setViewName("redirect:/apisettings");
			return mav;
		}

		mav.addObject("entity", entity);
		mav.addObject("apiType", entity.getApiType());
		mav.addObject("template", entity.getApiType().getTemplate());
		return mav;
	}

	@PostMapping("/apisettings/delete")
	@PreAuthorize("hasAuthority('" + CorePrivilege.API_SETTINGS_MODIFY_NAME + "')")
	public String deleteSetting(@RequestParam String apiLabel,
			RedirectAttributes redirectAttributes) {
		APIIntegrationEntity apiEntity = apiService.findByLabel(apiLabel);
		if (apiEntity == null) {
			redirectAttributes.addFlashAttribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,
					"Unknown API Label");
			return "redirect:/apisettings";
		}
		apiService.delete(apiEntity);
		return "redirect:/apisettings";
	}

	@PostMapping("/apisettings/update")
	@PreAuthorize("hasAuthority('" + CorePrivilege.API_SETTINGS_MODIFY_NAME + "')")
	public String updateSetting(@RequestParam String apiType,
			@RequestParam Optional<Long> apiId,
			@RequestParam Map<String, String> parameters,
			RedirectAttributes redirectAttributes) {
		ApiType api = ApiType.typeForName(apiType);
		if (api == null) {
			redirectAttributes.addFlashAttribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,
					"Unknown API");
			return "redirect:/apisettings";
		}
		try {
			APIIntegrationEntity incomingEntity = api.makeEntityForParams(parameters);
			apiId.ifPresent(id -> incomingEntity.setIntegrationId(id));
			apiService.upsertEntity(incomingEntity);
			redirectAttributes.addFlashAttribute(WatchtowerModelAndView.SUCCESS_NOTIFICATION,
					"Successfully updated " + incomingEntity.getApiLabel());
		} catch (ApiIntegrationException e) {
			redirectAttributes.addFlashAttribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,
					e.getMessage());
		}
		return "redirect:/apisettings";
	}

	@PostMapping("apisettings/testConnection")
	public String testConnection(@RequestParam String apiLabel,
			RedirectAttributes redirectAttributes) {
		APIIntegrationEntity entity = apiService.findByLabel(apiLabel);
		if (entity == null) {
			redirectAttributes.addFlashAttribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,
					"Unknown API Label");
			return "redirect:/apisettings";
		}
		try {
			IWatchtowerApi api = entity.createApi();
			api.testClientConnection();
			redirectAttributes.addFlashAttribute(WatchtowerModelAndView.SUCCESS_NOTIFICATION,
					"Success");
		} catch (ApiIntegrationException e) {
			redirectAttributes.addFlashAttribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,
					e.getMessage());
		}
		return "redirect:/apisettings";
	}
}
