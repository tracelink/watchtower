package com.tracelink.appsec.module.awssecurity;

import java.util.Objects;

/** Human-readable provider names and source folders, with a stable per-execution identity. */
final class AwsSecurityIdentity {
    private AwsSecurityIdentity() { }
    static String reviewTitle(AwsSecurityRun run) {
        // AWS accepts only ASCII letters, numbers, hyphens and underscores, up to 100 characters.
        // Keep the complete UUID and scan scope even when repository/integration names are long.
        var context=AwsSecuritySnapshot.decode(run.snapshotJson).context();
        String scope="setup".equals(run.parentType)?"sample-"+Objects.toString(run.setupMode,"FULL"):
            "pull_request".equals(run.parentType)?"pr-"+context.pullRequestId()+"-scan-"+run.parentId:"scan-"+run.parentId;
        String suffix=titlePart(scope,35)+"-"+run.id;
        String label=titlePart(context.repository(),55)+"-"+titlePart(context.apiLabel(),20);
        return label.substring(0,Math.min(label.length(),100-suffix.length()-1))+"-"+suffix;
    }
    /**
     * The title of a repository's one shared review: the same for every scan of it, so a review whose mapping was lost can be found
     * again. The repository id always survives truncation, which keeps two repositories with long similar names apart.
     */
    static String repositoryReviewTitle(AwsSecurityRun run) {
        var context=AwsSecuritySnapshot.decode(run.snapshotJson).context();
        String suffix="-r"+run.repositoryId;
        String label="watchtower-"+titlePart(context.apiLabel(),20)+"-"+titlePart(context.repository(),55);
        return label.substring(0,Math.min(label.length(),100-suffix.length()))+suffix;
    }
    /** Pre-fix titles are still needed to reconcile an already-issued create without duplication. */
    static String legacyReviewTitle(AwsSecurityRun run) {
        var context=AwsSecuritySnapshot.decode(run.snapshotJson).context();
        String scope="setup".equals(run.parentType)?"Sample "+Objects.toString(run.setupMode,"FULL"):
            "pull_request".equals(run.parentType)?"PR "+context.pullRequestId()+" - scan "+run.parentId:"scan "+run.parentId;
        return readable(context.repository(),55)+" - "+readable(context.apiLabel(),20)+" - "+readable(scope,50)+" - "+run.id;
    }
    private static String titlePart(String value,int max) {
        String text=Objects.toString(value,"repository").replaceAll("[^A-Za-z0-9_-]","-").replaceAll("-+","-");
        if(text.isBlank())text="repository";
        return text.substring(0,Math.min(max,text.length()));
    }
    static String inputPrefix(AwsSecurityRun run) {
        // A restarted preparation keeps the exact uploaded object keys, including older layouts.
        if(run.sourceKey!=null&&run.sourceKey.endsWith("/source.zip"))return run.sourceKey.substring(0,run.sourceKey.length()-"source.zip".length());
        var snapshot=AwsSecuritySnapshot.decode(run.snapshotJson);var context=snapshot.context();
        // <installation>/<integration>/<repository>/<scan type>/<scan id>/<execution>/1/. The installation level is the folder the
        // Agent Space and the role are scoped to, so everything else lives beneath it; the repository id keeps two
        // repositories with the same (or truncated) name apart; the execution keeps a retried scan's uploads immutable.
        boolean setup="setup".equals(run.parentType);
        String integration=setup?"setup":slug(context.apiLabel());
        String repository=setup?"sample-code":slug(context.repository())+"-r"+run.repositoryId;
        return "aws-security-inputs/"+snapshot.profile().installation()+"/"+integration+"/"+repository+"/"+
            run.parentType+"/"+run.parentId+"/"+run.id+"/1/";
    }
    private static String readable(String value,int max) {
        String text=Objects.toString(value,"repository").replaceAll("[\\p{Cntrl}\\s]+"," ").strip();
        return text.substring(0,Math.min(max,text.length()));
    }
    private static String slug(String value) {
        String text=Objects.toString(value,"repository").replaceAll("[^A-Za-z0-9._-]","-").replaceAll("-+","-");
        text=text.replaceAll("^\\.+|\\.+$","");return text.isBlank()?"repository":text.substring(0,Math.min(40,text.length()));
    }
}
