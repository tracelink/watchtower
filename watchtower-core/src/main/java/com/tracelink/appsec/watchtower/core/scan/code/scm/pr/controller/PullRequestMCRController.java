package com.tracelink.appsec.watchtower.core.scan.code.scm.pr.controller;

import com.tracelink.appsec.watchtower.core.auth.model.CorePrivilege;
import com.tracelink.appsec.watchtower.core.mvc.WatchtowerModelAndView;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.result.PullRequestMCRFilter;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.service.PRScanResultService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;

/**
 * Controller for handling getting high-level info about Pull Request Manual Code Reviews.
 *
 * @author droseen
 */
@Controller
@RequestMapping("/scan/mcr")
@PreAuthorize("hasAuthority('" + CorePrivilege.SCAN_RESULTS_NAME + "')")
public class PullRequestMCRController {

	private PRScanResultService resultService;

	private final List<PullRequestMCRFilter> allowedFilters =
			Arrays.asList(PullRequestMCRFilter.ALL, PullRequestMCRFilter.PENDING, PullRequestMCRFilter.PROGRESS, PullRequestMCRFilter.REVIEWED, PullRequestMCRFilter.RECOMMENDATIONS);

	public PullRequestMCRController(@Autowired PRScanResultService resultService) {
		this.resultService = resultService;
	}

	@GetMapping
	public WatchtowerModelAndView getResultsHome() {
		WatchtowerModelAndView wmav = new WatchtowerModelAndView("pull_requests/mcrs");
		wmav.addObject("filters", PullRequestMCRFilter.values());
		return wmav;
	}

	@GetMapping("/{filter}")
	public WatchtowerModelAndView getResultPage(@PathVariable String filter,
			@RequestParam Optional<Integer> page, RedirectAttributes redirectAttributes) {
		WatchtowerModelAndView wmav = new WatchtowerModelAndView("pull_requests/mcrs");
		int pageNum = page.orElse(0);
		if (pageNum < 0) {
			if (allowedFilters.contains(PullRequestMCRFilter.toFilter(filter))) {
				wmav.setViewName("redirect:/scan/mcr/" + filter + "?page=0");
				return wmav;
			} else {
				wmav.setViewName("redirect:/scan/mcr");
			}
		}
		wmav.addObject("filters", PullRequestMCRFilter.values());
		wmav.addObject("activeFilter", filter);
		wmav.addObject("activePageNum", pageNum);
		PullRequestMCRFilter resultFilter = PullRequestMCRFilter.toFilter(filter);
		if (resultFilter == null) {
			redirectAttributes.addFlashAttribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,
					"Unknown Filter");
			wmav.setViewName("redirect:/scan/mcr");
		} else {
			wmav.addObject("results",
					resultService.getScanMCRsWithFilters(resultFilter, 10, pageNum));
		}
		return wmav;
	}
}
