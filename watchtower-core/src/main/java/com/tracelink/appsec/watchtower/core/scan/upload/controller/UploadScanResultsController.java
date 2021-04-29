package com.tracelink.appsec.watchtower.core.scan.upload.controller;

import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import com.tracelink.appsec.watchtower.core.auth.model.CorePrivilege;
import com.tracelink.appsec.watchtower.core.mvc.WatchtowerModelAndView;
import com.tracelink.appsec.watchtower.core.scan.upload.result.UploadResultFilter;
import com.tracelink.appsec.watchtower.core.scan.upload.service.UploadScanResultService;

/**
 * Controller for handling getting high-level info about scan results.
 *
 * @author csmith
 */
@Controller
@RequestMapping("/uploadscan/results")
@PreAuthorize("hasAuthority('" + CorePrivilege.SCAN_RESULTS_NAME + "')")
public class UploadScanResultsController {

	private UploadScanResultService resultService;

	public UploadScanResultsController(@Autowired UploadScanResultService resultService) {
		this.resultService = resultService;
	}

	@GetMapping
	public WatchtowerModelAndView getResultsHome() {
		WatchtowerModelAndView wmav = new WatchtowerModelAndView("upload_scan/results");
		wmav.addObject("filters", UploadResultFilter.values());
		return wmav;
	}

	@GetMapping("/{filter}")
	public WatchtowerModelAndView getResultPage(@PathVariable String filter,
			@RequestParam Optional<Integer> page, RedirectAttributes redirectAttributes) {
		WatchtowerModelAndView wmav = new WatchtowerModelAndView("upload_scan/results");
		int pageNum = page.orElse(0);
		if (pageNum < 0) {
			wmav.setViewName("redirect:/uploadscan/results/" + filter + "?page=0");
			return wmav;
		}
		wmav.addObject("filters", UploadResultFilter.values());
		wmav.addObject("activeFilter", filter);
		wmav.addObject("activePageNum", pageNum);
		UploadResultFilter resultFilter = UploadResultFilter.toFilter(filter);
		if (resultFilter == null) {
			redirectAttributes.addFlashAttribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,
					"Unknown Filter");
			wmav.setViewName("redirect:/uploadscan/results");
		} else {
			wmav.addObject("results",
					resultService.getScanResultsWithFilters(resultFilter, 10, pageNum));
		}
		return wmav;
	}
}
