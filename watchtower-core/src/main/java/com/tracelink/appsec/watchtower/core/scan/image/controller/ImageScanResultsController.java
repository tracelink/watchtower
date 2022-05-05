package com.tracelink.appsec.watchtower.core.scan.image.controller;

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
import com.tracelink.appsec.watchtower.core.scan.image.result.ImageResultFilter;
import com.tracelink.appsec.watchtower.core.scan.image.service.ImageScanResultService;

/**
 * Controller to get information about the results of Image Scans
 * 
 * @author csmith
 *
 */
@Controller
@RequestMapping("/imagescan/results")
@PreAuthorize("hasAuthority('" + CorePrivilege.SCAN_RESULTS_NAME + "')")
public class ImageScanResultsController {

	private ImageScanResultService resultService;

	public ImageScanResultsController(@Autowired ImageScanResultService resultService) {
		this.resultService = resultService;
	}

	@GetMapping
	public WatchtowerModelAndView getResultsHome() {
		WatchtowerModelAndView wmav = new WatchtowerModelAndView("image_scan/results");
		wmav.addObject("filters", ImageResultFilter.values());
		return wmav;
	}

	@GetMapping("/{filter}")
	public WatchtowerModelAndView getResultPage(@PathVariable String filter,
			@RequestParam Optional<Integer> page, RedirectAttributes redirectAttributes) {
		WatchtowerModelAndView wmav = new WatchtowerModelAndView("image_scan/results");
		int pageNum = page.orElse(0);
		if (pageNum < 0) {
			wmav.setViewName("redirect:/imagescan/results/" + filter + "?page=0");
			return wmav;
		}

		ImageResultFilter resultFilter = ImageResultFilter.toFilter(filter);
		if (resultFilter == null) {
			redirectAttributes.addFlashAttribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,
					"Unknown Filter");
			wmav.setViewName("redirect:/imagescan/results");
		} else {
			wmav.addObject("filters", ImageResultFilter.values());
			wmav.addObject("activeFilter", filter);
			wmav.addObject("activePageNum", pageNum);
			wmav.addObject("results",
					resultService.getScanResultsWithFilters(resultFilter, 10, pageNum));
		}
		return wmav;
	}
}
