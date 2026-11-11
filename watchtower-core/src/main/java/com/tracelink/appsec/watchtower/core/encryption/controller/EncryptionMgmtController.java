package com.tracelink.appsec.watchtower.core.encryption.controller;

import java.security.Principal;
import java.util.concurrent.CompletableFuture;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import com.tracelink.appsec.watchtower.core.auth.model.CorePrivilege;
import com.tracelink.appsec.watchtower.core.encryption.model.EncryptionType;
import com.tracelink.appsec.watchtower.core.encryption.service.KeyRotationService;
import com.tracelink.appsec.watchtower.core.encryption.model.DataEncryptionKey;
import com.tracelink.appsec.watchtower.core.mvc.PagedResult;
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

	private static final Logger LOG = LoggerFactory.getLogger(EncryptionMgmtController.class);
	private static final String ENCRYPTION_REDIRECT = "redirect:/encryption";
	private final KeyRotationService keyRotationService;
	private final EncryptionType encryptionType;

	public EncryptionMgmtController(@Autowired KeyRotationService keyRotationService,
			@Value("${watchtower.encryption.type:none}") EncryptionType encryptionType) {
		this.keyRotationService = keyRotationService;
		this.encryptionType = encryptionType;
	}

	@GetMapping("")
	public WatchtowerModelAndView getEncryptionMgmt(@RequestParam(defaultValue = "0") int page) {
		WatchtowerModelAndView mv = new WatchtowerModelAndView("admin/encryption");
		if (page < 0) {
			mv.setViewName(ENCRYPTION_REDIRECT + "?page=0");
			return mv;
		}
		PageRequest pageable = PageRequest.of(page, 10, Sort.by("converterClassName"));
		Page<DataEncryptionKey> keys = keyRotationService.getKeys(pageable);
		if (keys == null) {
			var allKeys = keyRotationService.getKeys();
			keys = new PageImpl<>(allKeys, pageable, allKeys.size());
		}
		PagedResult<DataEncryptionKey> pagination = PagedResult.of(keys, key -> key);
		if (pagination.totalPages() > 0 && page >= pagination.totalPages()) {
			mv.setViewName(ENCRYPTION_REDIRECT + "?page=" + (pagination.totalPages() - 1));
			return mv;
		}
		mv.addObject("deks", pagination.content());
		mv.addObject("pagination", pagination);
		mv.addObject("metadata", keyRotationService.getEncryptionMetadata());
		// The active mode as a chip by the title (UAT walkthrough, 2026-10-16).
		mv.addObject("encryptionOn", encryptionType != EncryptionType.NONE);
		mv.addScriptReference("/scripts/encryption.js");
		return mv;
	}

	@PostMapping("rotate")
	@PreAuthorize("hasAuthority('" + CorePrivilege.ENCRYPTION_MODIFY_NAME + "')")
	public String rotateKeys(@RequestParam(required = false) Long keyId, Principal user,
			RedirectAttributes redirectAttributes) {
		LOG.info("{} started rotation of {}", user.getName(),
				keyId == null ? "all data-encryption keys" : "data-encryption key " + keyId);
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
			@RequestParam(required = false) Integer rotationPeriod, Principal user,
			RedirectAttributes redirectAttributes) {
		try {
			keyRotationService.enableRotationSchedule(enable, rotationPeriod);
			LOG.info("{} {} the key rotation schedule{}", user.getName(),
					enable ? "set" : "turned off",
					enable ? " to every " + rotationPeriod + " days" : "");
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
