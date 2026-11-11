package com.tracelink.appsec.module.awssecurity;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;
import com.tracelink.appsec.watchtower.core.scan.repository.RepositoryRepository;

/** Explicit, authorized POST controls. Spring Security's existing CSRF protection applies. */
@Controller
@PreAuthorize("hasAuthority('AWS Security Administration') and hasAuthority('Repository Settings View')")
public class AwsSecurityOperationsController {
    private final AwsSecurityAuditRepository audit;
    private final AwsSecurityPersistence persistence;
    private final AwsSecuritySettings settings;
    private final AwsSecurityClientGateway gateway;
    private final AwsSecurityRunRepository runs;
    private final AwsSecurityReadiness readiness;
    private final AwsSecurityCapacity capacity;
    @org.springframework.beans.factory.annotation.Autowired private AwsSecuritySetupAccess setupAccess;
    @org.springframework.beans.factory.annotation.Autowired private com.tracelink.appsec.watchtower.core.module.ModuleControlService moduleControls;
    @org.springframework.beans.factory.annotation.Autowired private AwsSecurityImporter reportImporter;
    @org.springframework.beans.factory.annotation.Autowired private AwsSecurityReviewDeletion reviewDeletion;
    @org.springframework.beans.factory.annotation.Autowired private AwsSecurityEvidencePolicy evidencePolicy;
    @org.springframework.beans.factory.annotation.Autowired private AwsSecurityFailurePolicyStore failurePolicyStore;
    @org.springframework.beans.factory.annotation.Autowired private com.tracelink.appsec.watchtower.core.ruleset.RulesetService rulesetService;
    /** The module's own provided ruleset always holds its rule; setup is done once a ruleset someone built runs it, directly or by including another. */
    private boolean reviewRuleIsInARuleset(){
        return rulesetService.getRulesets().stream().filter(ruleset->!ruleset.isProvided())
            .anyMatch(ruleset->ruleset.getAllRules().stream().anyMatch(rule->AwsSecurityModule.NAME.equalsIgnoreCase(rule.getModule())));
    }
    private AwsSecurityReadiness.Result setupReadiness(){
        var result=readiness.check();var checks=new java.util.ArrayList<>(result.checks());boolean shared=reportImporter.sharedArtifacts();
        checks.add(new AwsSecurityReadiness.Check("Scanner module policy",moduleControls.enabled(AwsSecurityModule.NAME)?"ENABLED":"DISABLED","Turn on AWS Security Agent under Scanner modules to scan repositories. Sample-code setup tests can run while it is off."));
        checks.add(new AwsSecurityReadiness.Check("Shared report storage",shared?"CONFIGURED":"FAILED",shared?"A shared location for scan results is configured. A completed setup test checks that results can be saved.":"Ask the deployment administrator to configure shared S3 storage for scan results before starting a setup test."));
        return new AwsSecurityReadiness.Result(result.ready()&&shared,result.verifiedAt(),shared?result.reason():"Shared S3 report storage is required before setup execution",java.util.List.copyOf(checks),result.runtimeArn());
    }
    public AwsSecurityOperationsController(AwsSecurityPersistence persistence, AwsSecuritySettings settings, AwsSecurityClientGateway gateway, AwsSecurityRunRepository runs, AwsSecurityAuditRepository audit, AwsSecurityReadiness readiness, AwsSecurityCapacity capacity) {
        this.audit=audit;
        this.persistence=persistence;
        this.settings=settings; this.gateway=gateway; this.runs=runs;
        this.readiness=readiness;
        this.capacity=capacity;
    }
    @GetMapping("/aws-security/readiness/view")
    public com.tracelink.appsec.watchtower.core.mvc.WatchtowerModelAndView readinessPage(@RequestParam(required = false) String tab, Authentication actor) {
        setupAccess.require(actor.getName());
        var view=new com.tracelink.appsec.watchtower.core.mvc.WatchtowerModelAndView("awssecurity/readiness").addScriptReference("/scripts/aws-security-setup.js");
        view.addObject("readiness",setupReadiness());view.addObject("awsProfile",settings.profile());view.addObject("awsScannerEnabled",moduleControls.enabled(AwsSecurityModule.NAME));view.addObject("awsActivationConfigured",settings.unavailable()==null&&moduleControls.enabled(AwsSecurityModule.NAME)&&reportImporter.sharedArtifacts());
        view.addObject("awsReviewInRuleset",reviewRuleIsInARuleset());view.addObject("awsHasScanRun",runs.hasScanRun());
        view.addObject("awsCapacity",capacity.snapshot());view.addObject("awsCapacityUsed",runs.activePermitCount());
        view.addObject("awsSourcePolicy", evidencePolicy.sourcePolicy());view.addObject("awsPassOnError", failurePolicyStore.passOnError());view.addObject("awsActiveTab", "settings".equals(tab) || "tests".equals(tab) ? tab : "status");return view;
    }
    /** The Settings tab's one Save: reviews at once and the "Show source for AWS findings" switch. Unchanged values write nothing. */
    @PostMapping("/aws-security/settings")
    public String updateSettings(@RequestParam String limit, @RequestParam(defaultValue = "false") boolean showSource,
            @RequestParam(required = false) Boolean bypassOnError,
            Authentication actor, org.springframework.web.servlet.mvc.support.RedirectAttributes flash) {
        setupAccess.require(actor.getName());
        int reviews = reviewsAtOnce(limit);
        if (reviews < 1 || reviews > 5) {
            // Said on the page; the browser's own bubble is not enforced for a script or an old tab
            flash.addFlashAttribute("failure", "Reviews at once must be a whole number from 1 to 5.");
            return "redirect:/aws-security/readiness/view?tab=settings";
        }
        boolean changed = false;
        if (reviews != capacity.limit()) { capacity.save(reviews, actor.getName()); changed = true; }
        changed |= evidencePolicy.saveSourceShown(showSource, actor.getName());
        // Absent means this form did not offer the choice: leave it as it is.
        if (bypassOnError != null) changed |= failurePolicyStore.savePassOnError(bypassOnError, actor.getName());
        flash.addFlashAttribute("success", changed ? "AWS settings saved. New scans use them; running reviews carry on." : "No changes to save.");
        return "redirect:/aws-security/readiness/view?tab=settings";
    }
    /** The number typed, or 0 when it is not a whole number. */
    static int reviewsAtOnce(String text) {
        try { return Integer.parseInt(text == null ? "" : text.trim()); } catch (NumberFormatException e) { return 0; }
    }
    @GetMapping("/aws-security/readiness") @ResponseBody
    public Object readiness(Authentication actor) {
        setupAccess.require(actor.getName());
        return setupReadiness();
    }
    @PostMapping("/aws-security/runs/{id}/delete-review")
    @PreAuthorize("hasAuthority('AWS Security Administration') and hasAuthority('Repository Settings View') and hasAuthority('Scan Results View')")
    public String deleteReview(@PathVariable String id,@RequestParam String reviewId,@RequestParam String confirmation,Authentication actor,org.springframework.web.servlet.mvc.support.RedirectAttributes flash) {
        String destination=reviewDeletion.delete(id,reviewId,confirmation,actor.getName());
        flash.addFlashAttribute("success","AWS review deleted. Saved Watchtower results and scan history are retained.");
        return "redirect:"+destination;
    }
    /**
     * Stop, retry and reconcile. Programmatic callers asking for JSON get the JSON receipt. A browser form post
     * is sent back to the page it came from with a plain message: the receipt alone left an empty page.
     */
    @PostMapping("/aws-security/runs/{id}/{action}") @ResponseBody @Transactional
    public Object operate(@PathVariable String id, @PathVariable String action, Authentication actor,
            @RequestHeader(value="Accept",required=false) String accept,
            @RequestHeader(value="HX-Request",required=false) String boosted,
            @RequestHeader(value="Referer",required=false) String referer,
            org.springframework.web.servlet.mvc.support.RedirectAttributes flash) {
        var row = runs.findById(id).orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND));
        if ("stop".equals(action)) persistence.requestStop(id);
        else if ("retry-import".equals(action)) persistence.retryImport(id);
        else if ("reconcile".equals(action) || "retry-cleanup".equals(action)) persistence.scheduleRecovery(id);
        else throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
        audit.save(new AwsSecurityAudit(action, actor.getName(), id));
        // The page's htmx boost sends Accept */*, so it is a browser by its HX-Request header, not by Accept.
        if (boosted != null || (accept != null && accept.contains("text/html"))) {
            flash.addFlashAttribute("success", requestedMessage(action));
            return new org.springframework.web.servlet.ModelAndView("redirect:" + backTo(referer));
        }
        return java.util.Map.of("run", row.id, "action", action, "state", "Requested");
    }
    static String requestedMessage(String action) {
        return switch (action) {
            case "stop" -> "Stop requested. The review stops at its next safe point; results already imported are kept.";
            case "retry-import" -> "Import retry requested. Reload in a moment to see whether the findings arrived.";
            case "retry-cleanup" -> "Cleanup retry requested.";
            default -> "Reconcile requested. Watchtower is checking the review with AWS; reload in a moment to see the result.";
        };
    }
    /** The page the form was on, when it is one of ours; otherwise the AWS status page. Never an outside address. */
    static String backTo(String referer) {
        String fallback = "/aws-security/readiness/view";
        if (referer == null || referer.isBlank()) return fallback;
        try {
            var uri = java.net.URI.create(referer);
            String path = uri.getRawPath();
            if (path == null || !path.startsWith("/") || path.startsWith("//") || path.contains("\\")) return fallback;
            return uri.getRawQuery() == null ? path : path + "?" + uri.getRawQuery();
        } catch (IllegalArgumentException e) {
            return fallback;
        }
    }
}
