package com.tracelink.appsec.watchtower.core.scan.code.scm.pr.controller;

import java.util.List;
import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
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
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.mergegate.MergeGateService;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.result.PRResultFilter;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.result.PRResultPeriod;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.result.PRResultTab;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.service.PRScanResultService;
import com.tracelink.appsec.watchtower.core.scan.presentation.HomeActivityItem;

/**
 * Controller for handling getting high-level info about scan results.
 *
 * @author csmith
 */
@Controller
@RequestMapping("/scan/results")
@PreAuthorize("hasAuthority('" + CorePrivilege.SCAN_RESULTS_NAME + "')")
public class PRScanResultsController {

	private static final Logger LOG = LoggerFactory.getLogger(PRScanResultsController.class);

	/** The merge gate view's windows, in days. */
	static final List<Integer> MERGE_GATE_DAYS = List.of(7, MergeGateService.DEFAULT_DAYS,
			MergeGateService.MAX_DAYS);

	private PRScanResultService resultService;

	private final MergeGateService mergeGateService;

	public PRScanResultsController(@Autowired PRScanResultService resultService,
			@Autowired MergeGateService mergeGateService) {
		this.resultService = resultService;
		this.mergeGateService = mergeGateService;
	}

	/**
	 * Merges in a window by what Watchtower knew when each happened: what enforcing a merge
	 * gate would change. Mapped before {@code /{filter}}, which a literal path outranks.
	 */
	@GetMapping("/" + PRResultTab.MERGE_GATE)
	public WatchtowerModelAndView getMergeGate(
			@RequestParam(defaultValue = "" + MergeGateService.DEFAULT_DAYS) String days) {
		WatchtowerModelAndView wmav = new WatchtowerModelAndView("pull_requests/mergegate");
		int window = MERGE_GATE_DAYS.stream().filter(d -> String.valueOf(d).equals(days))
				.findFirst().orElse(MergeGateService.DEFAULT_DAYS);
		wmav.addObject("filters", PRResultTab.all());
		wmav.addObject("activeFilter", PRResultTab.MERGE_GATE);
		wmav.addObject("dayOptions", MERGE_GATE_DAYS);
		wmav.addObject("report", mergeGateService.report(window));
		return wmav;
	}

	@GetMapping
	public WatchtowerModelAndView getResultsHome() {
		WatchtowerModelAndView wmav = new WatchtowerModelAndView("pull_requests/results");
		wmav.setViewName("redirect:/scan/results/all");
		return wmav;
	}

	/**
	 * One page of a filter's results: the last 90 days ({@code period=recent}, the default) or
	 * before them ({@code period=older}).
	 */
	@GetMapping("/{filter}")
	public WatchtowerModelAndView getResultPage(@PathVariable String filter,
			@RequestParam Optional<Integer> page,
			@RequestParam(defaultValue = "recent") String period,
			RedirectAttributes redirectAttributes) {
		WatchtowerModelAndView wmav = new WatchtowerModelAndView("pull_requests/results");
		PRResultPeriod resultPeriod = PRResultPeriod.of(period);
		String periodQuery = "?period=" + resultPeriod.getKey();
		int pageNum = page.orElse(0);
		if (pageNum < 0) {
			wmav.setViewName("redirect:/scan/results/" + filter + periodQuery + "&page=0");
			return wmav;
		}
		wmav.addObject("activeFilter", filter);
		wmav.addObject("activePageNum", pageNum);
		wmav.addObject("periods", PRResultPeriod.values());
		wmav.addObject("period", resultPeriod);
		// Kept by the filter tabs and the pager
		wmav.addObject("filterQuery", periodQuery);
		PRResultFilter resultFilter = PRResultFilter.toFilter(filter);
		if (resultFilter == null) {
			redirectAttributes.addFlashAttribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,
					"Unknown Filter");
			wmav.setViewName("redirect:/scan/results/all");
		} else {
			long start = System.currentTimeMillis();
			var pagedResult = resultService.getScanResultsWithFilters(resultFilter, resultPeriod,
					10, pageNum);
			if (pagedResult.totalPages() > 0 && pageNum >= pagedResult.totalPages()) {
				wmav.setViewName("redirect:/scan/results/" + filter + periodQuery + "&page="
						+ (pagedResult.totalPages() - 1));
				return wmav;
			}
			LOG.info("getResultPage: filter={} page={} getScanResultsWithFilters took {} ms for {} row(s)",
					filter, pageNum, System.currentTimeMillis() - start, pagedResult.content().size());
			// Added only once the page renders: a redirect copies model values into its URL,
			// and a list of tabs has no URL form
			wmav.addObject("filters", PRResultTab.all());
			wmav.addObject("results", pagedResult.content());
			wmav.addObject("activityRows", pagedResult.content().stream()
					.map(HomeActivityItem::fromPullRequestResult).toList());
			wmav.addObject("hasNext", pagedResult.hasNext());
			wmav.addObject("pagination", pagedResult);
		}
		return wmav;
	}
}
