package com.tracelink.appsec.watchtower.core.encryption.controller;

import java.util.concurrent.CompletableFuture;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import com.tracelink.appsec.watchtower.core.auth.model.CorePrivilege;
import com.tracelink.appsec.watchtower.core.encryption.service.KeyRotationService;
import com.tracelink.appsec.watchtower.core.mvc.WatchtowerModelAndView;

/**
 * Controller for the encryption management page. Allows manual rotation of keys and configuration
 * of auto-rotation schedule.
 *
 * @author mcool
 */
@Controller
@RequestMapping("/encryption")
@PreAuthorize("hasAuthority('" + CorePrivilege.ENCRYPTION_VIEW_NAME + "')")
public class EncryptionMgmtController {

	private static final String ENCRYPTION_REDIRECT = "redirect:/encryption";
	private final KeyRotationService keyRotationService;

	public EncryptionMgmtController(@Autowired KeyRotationService keyRotationService) {
		this.keyRotationService = keyRotationService;
	}

	@GetMapping("")
	public WatchtowerModelAndView getEncryptionMgmt() {
		WatchtowerModelAndView mv = new WatchtowerModelAndView("admin/encryption");
		mv.addObject("deks", keyRotationService.getKeys());
		mv.addObject("metadata", keyRotationService.getEncryptionMetadata());
		mv.addScriptReference("/scripts/encryption.js");
		return mv;
	}

	@PostMapping("rotate")
	@PreAuthorize("hasAuthority('" + CorePrivilege.ENCRYPTION_MODIFY_NAME + "')")
	public String rotateKeys(@RequestParam(required = false) Long keyId,
			RedirectAttributes redirectAttributes) {
		if (keyId == null) {
			CompletableFuture.runAsync(keyRotationService::rotateKeys);
		} else {
			CompletableFuture.runAsync(() -> keyRotationService.rotateKey(keyId));
		}
		redirectAttributes.addFlashAttribute(WatchtowerModelAndView.SUCCESS_NOTIFICATION,
				"Key rotation in progress");
		return ENCRYPTION_REDIRECT;
	}

	@PostMapping("rotate/schedule")
	@PreAuthorize("hasAuthority('" + CorePrivilege.ENCRYPTION_MODIFY_NAME + "')")
	public String enableRotationSchedule(@RequestParam boolean enable,
			@RequestParam(required = false) Integer rotationPeriod,
			RedirectAttributes redirectAttributes) {
		try {
			keyRotationService.enableRotationSchedule(enable, rotationPeriod);
			String message = String.format("Successfully %s rotation schedule",
					enable ? "updated" : "disabled");
			redirectAttributes
					.addFlashAttribute(WatchtowerModelAndView.SUCCESS_NOTIFICATION, message);
		} catch (IllegalArgumentException e) {
			redirectAttributes
					.addFlashAttribute(WatchtowerModelAndView.FAILURE_NOTIFICATION, e.getMessage());
		}
		return ENCRYPTION_REDIRECT;
	}
}
