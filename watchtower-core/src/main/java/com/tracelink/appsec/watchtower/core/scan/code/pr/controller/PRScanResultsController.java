package com.tracelink.appsec.watchtower.core.scan.code.pr.controller;

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
import com.tracelink.appsec.watchtower.core.scan.code.pr.result.PRResultFilter;
import com.tracelink.appsec.watchtower.core.scan.code.pr.service.PRScanResultService;

/**
 * Controller for handling getting high-level info about scan results.
 *
 * @author csmith
 */
@Controller
@RequestMapping("/scan/results")
@PreAuthorize("hasAuthority('" + CorePrivilege.SCAN_RESULTS_NAME + "')")
public class PRScanResultsController {

	private PRScanResultService resultService;

	public PRScanResultsController(@Autowired PRScanResultService resultService) {
		this.resultService = resultService;
	}

	@GetMapping
	public WatchtowerModelAndView getResultsHome() {
		WatchtowerModelAndView wmav = new WatchtowerModelAndView("pull_requests/results");
		wmav.addObject("filters", PRResultFilter.values());
		return wmav;
	}

	@GetMapping("/{filter}")
	public WatchtowerModelAndView getResultPage(@PathVariable String filter,
			@RequestParam Optional<Integer> page, RedirectAttributes redirectAttributes) {
		WatchtowerModelAndView wmav = new WatchtowerModelAndView("pull_requests/results");
		int pageNum = page.orElse(0);
		if (pageNum < 0) {
			wmav.setViewName("redirect:/scan/results/" + filter + "?page=0");
			return wmav;
		}
		wmav.addObject("filters", PRResultFilter.values());
		wmav.addObject("activeFilter", filter);
		wmav.addObject("activePageNum", pageNum);
		PRResultFilter resultFilter = PRResultFilter.toFilter(filter);
		if (resultFilter == null) {
			redirectAttributes.addFlashAttribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,
					"Unknown Filter");
			wmav.setViewName("redirect:/scan/results");
		} else {
			wmav.addObject("results",
					resultService.getScanResultsWithFilters(resultFilter, 10, pageNum));
		}
		return wmav;
	}
}
