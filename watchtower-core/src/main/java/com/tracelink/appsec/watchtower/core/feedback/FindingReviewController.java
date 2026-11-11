package com.tracelink.appsec.watchtower.core.feedback;

import org.springframework.stereotype.Controller;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import com.tracelink.appsec.watchtower.core.mvc.*;

@Controller
@RequestMapping("/finding-feedback/review")
@PreAuthorize("hasAuthority('Scan Results View') and hasAuthority('Finding Feedback')")
public class FindingReviewController {
    private final FindingReviewService reviews;
    private final com.tracelink.appsec.watchtower.core.scan.code.scm.pr.service.PRScanResultService prResults;
    private final com.tracelink.appsec.watchtower.core.scan.code.report.ScanReportReader scanReports;
    public FindingReviewController(FindingReviewService reviews,
            com.tracelink.appsec.watchtower.core.scan.code.scm.pr.service.PRScanResultService prResults,
            com.tracelink.appsec.watchtower.core.scan.code.report.ScanReportReader scanReports) {
        this.reviews = reviews;
        this.prResults = prResults;
        this.scanReports = scanReports;
    }
    @ExceptionHandler(IllegalArgumentException.class) @ResponseBody
    @ResponseStatus(org.springframework.http.HttpStatus.BAD_REQUEST)
    public java.util.Map<String, String> invalid() { return java.util.Map.of("error", "Check the scan, occurrence and paging parameters."); }

    @GetMapping
    public WatchtowerModelAndView page(@RequestParam String scanType, @RequestParam long scanId,
            @RequestParam String findingKey, @RequestParam(defaultValue = "0") int providerPage,
            @RequestParam(required = false) String returnTo) {
        var view = new WatchtowerModelAndView("feedback/review");
        var review = reviews.workspace(scanType, scanId, findingKey, providerPage, returnTo);
        view.addObject("review", review);
        view.addObject("sourceUrl", sourceUrl(review));
        view.addObject("secretsScanned", secretsScanned(review));
        String module = reviews.scannerModule(scanType, scanId, findingKey);
        view.addObject("scanner", module == null || module.isBlank() ? null
                : com.tracelink.appsec.watchtower.core.scan.presentation.ScannerIdentity.of(module));
        return view;
    }
    /**
     * The reviewed finding's code for "View source" (UAT walkthrough, 2026-10-15): pull request
     * findings only; repository findings use the repository report's own code endpoint.
     */
    @GetMapping("/source")
    public String source(@RequestParam String scanType, @RequestParam long scanId,
            @RequestParam String findingKey, org.springframework.ui.Model model) {
        if (!"pull_request".equals(scanType)) {
            throw new IllegalArgumentException("Source is available for pull request findings only");
        }
        var source = prResults.reviewSource(scanId, Long.parseLong(findingKey));
        model.addAttribute("file", source.map(found -> found.file()).orElse(null));
        model.addAttribute("link", source.map(found -> found.link()).orElse(null));
        return "feedback/source :: source";
    }

    /** Whether a secrets scanner ran on the reviewed scan, so the source panel may say lines are masked. */
    private boolean secretsScanned(FindingReviewService.Workspace review) {
        if (review.selected() == null) return false;
        try {
            return scanReports.secretsScannerRan(review.scanType(), review.scanId());
        } catch (org.springframework.web.server.ResponseStatusException unknownScan) {
            return false;
        }
    }

    /** Where "View source" loads code from, or null when this scan type keeps no source. */
    static String sourceUrl(FindingReviewService.Workspace review) {
        if (review.selected() == null || review.selected().file() == null) return null;
        var builder = org.springframework.web.util.UriComponentsBuilder.newInstance();
        return switch (review.scanType()) {
            case "pull_request" -> builder.path("/finding-feedback/review/source")
                    .queryParam("scanType", "{type}").queryParam("scanId", "{id}").queryParam("findingKey", "{key}")
                    .encode().buildAndExpand(review.scanType(), review.scanId(), review.selected().key()).toUriString();
            case "repository" -> builder.path("/reposcan/report/{id}/code").queryParam("file", "{file}")
                    .encode().buildAndExpand(review.scanId(), review.selected().file()).toUriString();
            default -> null;
        };
    }

    @GetMapping("/items") @ResponseBody
    public PagedResult<FindingReviewService.Item> items(@RequestParam String scanType, @RequestParam long scanId,
            @RequestParam String findingKey, @RequestParam(defaultValue = "") String search,
            @RequestParam(defaultValue = "0") int page, @RequestParam(defaultValue = "25") int pageSize) {
        return reviews.items(scanType, scanId, findingKey, search, page, pageSize);
    }
    @GetMapping("/history") @ResponseBody
    public PagedResult<FindingReviewService.History> history(@RequestParam String scanType, @RequestParam long scanId,
            @RequestParam String findingKey, @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "25") int pageSize) {
        return reviews.history(scanType, scanId, findingKey, page, pageSize);
    }
}
