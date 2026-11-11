package com.tracelink.appsec.watchtower.core.rule.workflow;

import java.util.*;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.http.*;
import org.springframework.web.util.UriComponentsBuilder;
import com.tracelink.appsec.watchtower.core.mvc.*;
import com.tracelink.appsec.watchtower.core.rule.*;
import com.tracelink.appsec.watchtower.core.metrics.RuleHealthService;

@Controller
@RequestMapping("/rules")
@PreAuthorize("hasAuthority('Rule Modify') or hasAuthority('Ruleset View')")
public class RuleWorkflowController {
    private final RuleReviewService reviews;
    private final RuleReviewWorkspace workspace;
    private final RuleHealthService health;
    @org.springframework.beans.factory.annotation.Autowired private com.tracelink.appsec.watchtower.core.rule.candidate.RuleCandidateService candidates;
    public RuleWorkflowController(RuleReviewService reviews, RuleReviewWorkspace workspace, RuleHealthService health) { this.reviews = reviews; this.workspace = workspace; this.health = health; }

    @GetMapping("/{id}/candidates") @PreAuthorize("hasAuthority('Rule Modify')")
    public WatchtowerModelAndView candidates(@PathVariable long id,@RequestParam(required=false) String caseId) {
        var rule=reviews.current(id);var mav=new WatchtowerModelAndView("rules/candidates").addScriptReference("/scripts/rule-candidates.js");
        mav.addObject("rule",rule);mav.addObject("example",caseId==null?null:candidates.caseReference(id,caseId));
        mav.addObject("scanner", com.tracelink.appsec.watchtower.core.scan.presentation.ScannerIdentity.of(rule.getModule()));
        mav.addObject("ruleName", com.tracelink.appsec.watchtower.core.scan.presentation.ScannerIdentity.withoutScannerPrefix(rule.getName()));
        return mav;
    }

    @GetMapping("/{id}/health")
    @PreAuthorize("hasAuthority('Scan Results View') and (hasAuthority('Rule Modify') or hasAuthority('Ruleset View'))")
    public WatchtowerModelAndView health(@PathVariable long id, @RequestParam(required=false) String revision,
            @RequestParam(defaultValue="90") int days, @RequestParam(defaultValue="all") String scanType, @RequestParam(defaultValue="all") String policy) {
        var rule = reviews.current(id); String selected = revision(rule, revision);
        var mav = base("rules/health", rule, selected, days, scanType, policy);
        var calculated = health.health(id, selected, days, scanType, policy);
        mav.addObject("health", calculated);
        mav.addObject("healthView", RuleDetailPresentation.health(calculated, health.minimumSample()));
        mav.addObject("reviewCount", workspace.reviews(id, selected, "all", "", 0, 1).totalElements());
        mav.addObject("revisions", health.revisions(id)); return mav;
    }
    @GetMapping("/{id}/reviews")
    public WatchtowerModelAndView reviews(@PathVariable long id, @RequestParam(required=false) String revision,
            @RequestParam(defaultValue="90") int days, @RequestParam(defaultValue="all") String scanType, @RequestParam(defaultValue="all") String policy,
            @RequestParam(required=false) String reviewId, @RequestParam(defaultValue="all") String state,
            @RequestParam(defaultValue="") String search, @RequestParam(defaultValue="0") int page, @RequestParam(defaultValue="25") int pageSize,
            @RequestParam(defaultValue="false") boolean compose) {
        var rule = reviews.current(id); var selectedReview = workspace.selected(id, reviewId);
        String selected = revision(rule, revision == null && selectedReview != null ? Objects.toString(selectedReview.revision(), "unknown") : revision);
        var mav = base("rules/reviews", rule, selected, days, scanType, policy).addScriptReference("/scripts/rule-reviews.js");
        mav.addObject("rows", workspace.reviews(id, selected, state, search, page, pageSize));
        mav.addObject("selectedReview", selectedReview); mav.addObject("state", state); mav.addObject("search", search);
        mav.addObject("canCreate", Objects.equals(selected, rule.getRevision()));
        mav.addObject("statuses", RuleDetailPresentation.REVIEW_STATUSES);
        // "New review" from an open review links back here with compose=true and opens the form.
        mav.addObject("openDialog", selectedReview != null || compose);
        mav.addObject("scopeChip", RuleDetailPresentation.scopeChip(selected, rule.getRevision(), days, scanType, policy));
        mav.addObject("pageUrl", UriComponentsBuilder.fromPath("/rules/" + id + "/reviews").queryParam("revision", Objects.toString(selected,"unknown"))
                .queryParam("days", days).queryParam("scanType", scanType).queryParam("policy", policy).queryParam("state", state).queryParam("search", search).queryParam("pageSize", pageSize).build().encode().toUriString());
        return mav;
    }
    @GetMapping("/{id}/reviews/evidence") @ResponseBody
    public PagedResult<RuleReviewWorkspace.Evidence> evidence(@PathVariable long id, @RequestParam(required=false) String revision,
            @RequestParam String kind, @RequestParam(defaultValue="") String search, @RequestParam(defaultValue="0") int page, @RequestParam(defaultValue="25") int pageSize, Authentication actor) {
        if (Set.of("finding", "scan").contains(kind) && actor.getAuthorities().stream().noneMatch(a -> a.getAuthority().equals("Scan Results View")))
            throw new org.springframework.security.access.AccessDeniedException("Scan evidence requires Scan Results View");
        return workspace.evidence(id, revision(reviews.current(id), revision), kind, search, page, pageSize);
    }
    @GetMapping("/{id}/reviews/options") @ResponseBody
    public PagedResult<RuleReviewWorkspace.Review> reviewOptions(@PathVariable long id,@RequestParam(required=false) String revision,
            @RequestParam(defaultValue="") String search,@RequestParam(defaultValue="0") int page,@RequestParam(defaultValue="25") int pageSize) {
        return workspace.reviews(id,revision(reviews.current(id),revision),"pending",search,page,pageSize);
    }
    @GetMapping("/{id}/reviews/{reviewId}/history") @ResponseBody
    public PagedResult<RuleReviewWorkspace.Audit> audit(@PathVariable long id, @PathVariable String reviewId,
            @RequestParam(defaultValue="0") int page, @RequestParam(defaultValue="25") int pageSize) {
        return workspace.audit(id, reviewId, page, pageSize);
    }
    private WatchtowerModelAndView base(String view, RuleDto rule, String revision, int days, String scanType, String policy) {
        if (days < 1 || days > 90 || !Set.of("all","pull_request","upload","repository").contains(scanType) || !Set.of("all","blocking","nonblocking","unknown").contains(policy)) throw new IllegalArgumentException("Invalid scope");
        var mav = new WatchtowerModelAndView(view); mav.addObject("rule", rule); mav.addObject("revision", revision);
        mav.addObject("scanner", com.tracelink.appsec.watchtower.core.scan.presentation.ScannerIdentity.of(rule.getModule()));
        mav.addObject("ruleName", com.tracelink.appsec.watchtower.core.scan.presentation.ScannerIdentity.withoutScannerPrefix(rule.getName()));
        mav.addObject("days", days); mav.addObject("scanType", scanType); mav.addObject("policy", policy);
        mav.addObject("scope", "?revision=" + Objects.toString(revision,"unknown") + "&days=" + days + "&scanType=" + scanType + "&policy=" + policy);
        return mav;
    }
    private static String revision(RuleDto rule, String value) { String result = value == null ? rule.getRevision() : "unknown".equals(value) ? null : value; RuleReviewWorkspace.revision(result); return result; }
    @ExceptionHandler(IllegalArgumentException.class) @ResponseBody
    public ResponseEntity<?> invalid(IllegalArgumentException error) { return ResponseEntity.badRequest().body(Map.of("error", "Check the rule, revision, filters and page size.")); }
}
