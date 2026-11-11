package com.tracelink.appsec.watchtower.core.scan.presentation;

import java.util.*;
import com.tracelink.appsec.watchtower.core.scan.code.RemoteAssessmentService;
import com.tracelink.appsec.watchtower.core.mvc.WatchtowerModelAndView;

/** Adds remote status and one bounded provider page to the existing report workspace. */
public final class RemoteReportModel {
    private RemoteReportModel() { }
    public static List<FindingPresentationModel> add(WatchtowerModelAndView model, String type, long id,
            RemoteAssessmentService service, List<FindingPresentationModel> local) {
        var statuses = service == null ? List.<RemoteAssessmentService.Status>of() : service.status(type, id);
        int page = 0;
        var attributes = org.springframework.web.context.request.RequestContextHolder.getRequestAttributes();
        if (attributes instanceof org.springframework.web.context.request.ServletRequestAttributes request) {
            try { page = Math.max(0, Math.min(999, Integer.parseInt(request.getRequest().getParameter("providerPage")))); }
            catch (NumberFormatException ignored) { }
        }
        String base = ("repository".equals(type) ? "/reposcan/report/" : "/scan/report/") + id;
        model.addObject("providerStatuses", statuses); model.addObject("providerPage", page);
        model.addObject("providerBase", base); model.addObject("providerIncomplete", statuses.stream().anyMatch(s -> !s.complete()));
        model.addObject("providerPages", statuses.stream().mapToInt(RemoteAssessmentService.Status::pages).max().orElse(0));
        List<FindingPresentationModel> findings = service==null?new ArrayList<>():new ArrayList<>(service.findings(type,id,page));
        if (!statuses.isEmpty()) findings.sort(Comparator.comparingInt((FindingPresentationModel f) ->
            "CRITICAL".equals(f.getSeverityFilterKey()) ? 0 : "UNKNOWN".equals(f.getSeverityFilterKey()) ? 7 : f.getSeverityValue())
            .thenComparingInt(f -> { String confidence = f.getProviderDetails() == null ? null : f.getProviderDetails().confidence();
                int rank = java.util.Arrays.asList("HIGH", "MEDIUM", "LOW").indexOf(confidence); return rank < 0 ? 3 : rank; })
            .thenComparing(f -> Objects.toString(f.getFileName(), ""))
            .thenComparingInt(f -> f.getLineNumber() == null ? 0 : f.getLineNumber())
            .thenComparing(FindingPresentationModel::getId));
        model.addObject("providerFindings",findings);
        model.addObject("providerImported",statuses.stream().mapToInt(RemoteAssessmentService.Status::imported).sum());
        model.addObject("workspaceFindings", workspace(findings, local));
        return local;
    }

    /**
     * One findings list for the report's single workspace: AWS and local findings together, most
     * severe first (the sort is stable, so each source keeps its own order within a severity).
     */
    static List<FindingPresentationModel> workspace(List<FindingPresentationModel> provider, List<FindingPresentationModel> local) {
        var all = new ArrayList<FindingPresentationModel>(provider.size() + local.size());
        all.addAll(provider);
        all.addAll(local);
        if (!provider.isEmpty() && !local.isEmpty()) all.sort(Comparator.comparingInt(FindingPresentationModel::getSeverityValue));
        return List.copyOf(all);
    }

    /**
     * The report's "By rule" rows with each remote assessment's rule added: "AWS Security Agent ·
     * Security review" with the findings it imported, so the tab counts AWS rules too.
     */
    public static List<Map.Entry<String, Integer>> withProviderRules(List<Map.Entry<String, Integer>> local,
            List<RemoteAssessmentService.Status> statuses) {
        var rows = new ArrayList<>(local);
        for (var status : statuses) {
            if (status.imported() <= 0) continue;
            String rule = status.ruleName() == null ? "AWS Security Agent" : "AWS Security Agent · " + status.ruleName();
            rows.add(Map.entry(rule, status.imported()));
        }
        rows.sort(Map.Entry.<String, Integer>comparingByValue().reversed());
        return List.copyOf(rows);
    }
}
