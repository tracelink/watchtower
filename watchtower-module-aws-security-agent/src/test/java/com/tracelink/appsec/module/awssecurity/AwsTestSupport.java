package com.tracelink.appsec.module.awssecurity;
import java.util.*;
import java.io.IOException;
import com.tracelink.appsec.watchtower.core.scan.code.*;
import com.tracelink.appsec.watchtower.core.rule.*;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.report.RepoReportStore;

final class AwsTestSupport {
    static AwsSecuritySettings settings() { return settings("arn:aws:kms:us-east-1:123456789012:key/one"); }
    static AwsSecuritySettings settings(String kmsKey) { return settings(kmsKey, "logs"); }
    static AwsSecuritySettings settings(String kmsKey, String logGroup) { return new AwsSecuritySettings("us-east-1","123456789012","space",
        "arn:aws:iam::123456789012:role/security","inputs",kmsKey,logGroup,"test","https://sqs.us-east-1.amazonaws.com/123456789012/aws-security.fifo",14400); }
    static AwsSecuritySnapshot snapshot(String execution, CodeScanType type) {
        var rule = new AwsSecurityRuleDto(); rule.setId(7L); rule.setName("AWS policy"); rule.setPriority(RulePriority.HIGH);
        return new AwsSecuritySnapshot(new ScanExecutionContext(execution,type,1,2,"bb","repo","main","a".repeat(40),
            type == CodeScanType.PULL_REQUEST ? "1" : null,"main","b".repeat(40),"c".repeat(40)), settings().profile(),rule.getExecutionIdentity(),rule.getName(),RulePriority.HIGH,rule.getRevision());
    }
    static AwsSecurityRun run() {
        var run = new AwsSecurityRun(); run.id=UUID.randomUUID().toString(); run.parentId=1; run.repositoryId=2;
        run.parentType="pull_request"; run.snapshotJson=snapshot("one",CodeScanType.PULL_REQUEST).encode();
        run.reviewId="review"; run.jobId="job"; run.providerStatus="COMPLETED"; run.stage=AwsSecurityRun.Stage.IMPORTING;
        run.providerTerminal=true; run.terminalAt=System.currentTimeMillis(); run.deadlineAt=System.currentTimeMillis()+14400000; return run;
    }
    static class MemoryStore implements RepoReportStore {
        final Map<String,byte[]> objects=new LinkedHashMap<>();
        public void put(String key,byte[] bytes,String type) throws IOException { if(objects.putIfAbsent(key,bytes)!=null)throw new IOException("Immutable object overwritten"); }
        public Optional<byte[]> get(String key){return Optional.ofNullable(objects.get(key));}
        public void copy(String from,String to)throws IOException{put(to,objects.get(from),"");}
        public boolean isShared(){return true;}
    }
}
