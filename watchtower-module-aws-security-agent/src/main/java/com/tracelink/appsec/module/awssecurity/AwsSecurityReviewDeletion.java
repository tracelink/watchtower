package com.tracelink.appsec.module.awssecurity;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.http.HttpStatus;

/** Explicit, audited provider deletion. Watchtower results and scan history are retained. */
@Service
public class AwsSecurityReviewDeletion {
    private final AwsSecurityRunRepository runs;
    private final AwsSecurityClientGateway gateway;
    private final AwsSecuritySettings settings;
    private final AwsSecurityAuditRepository audit;
    public AwsSecurityReviewDeletion(AwsSecurityRunRepository runs,AwsSecurityClientGateway gateway,AwsSecuritySettings settings,AwsSecurityAuditRepository audit){this.runs=runs;this.gateway=gateway;this.settings=settings;this.audit=audit;}
    @Transactional
    public String delete(String id,String reviewId,String confirmation,String actor) {
        var run=runs.locked(id).orElseThrow(()->new ResponseStatusException(HttpStatus.NOT_FOUND));
        if(!"DELETE".equals(confirmation)||run.reviewId==null||!run.reviewId.equals(reviewId))throw new ResponseStatusException(HttpStatus.BAD_REQUEST,"Confirm the AWS review to delete");
        if(run.sharedReview)throw new ResponseStatusException(HttpStatus.CONFLICT,"This AWS review is shared by every scan of the repository, so it cannot be deleted for one scan");
        if(run.providerDeleted)return destination(run);
        if(!run.finished()||!run.providerTerminal||!run.cleanupComplete||run.needsReconciliation||run.owner!=null&&run.leaseUntil>System.currentTimeMillis())
            throw new ResponseStatusException(HttpStatus.CONFLICT,"Wait for the scan, saved results and temporary code cleanup to finish before deleting the AWS review");
        var profile=AwsSecuritySnapshot.decode(run.snapshotJson).profile();
        if(!settings.profile().revision().equals(profile.revision()))throw new ResponseStatusException(HttpStatus.CONFLICT,"Restore this scan's AWS connection configuration before deleting its review");
        if(!gateway.retire(profile,run.reviewId))throw new ResponseStatusException(HttpStatus.CONFLICT,"AWS did not confirm deletion. The saved Watchtower results are unchanged");
        run.providerDeleted=true;run.dueAt=Long.MAX_VALUE;runs.saveAndFlush(run);audit.save(new AwsSecurityAudit("delete-aws-review",actor,run.id));
        return destination(run);
    }
    private String destination(AwsSecurityRun run){return "setup".equals(run.parentType)?"/aws-security/readiness/view":("repository".equals(run.parentType)?"/reposcan/report/":"/scan/report/")+run.parentId;}
}
