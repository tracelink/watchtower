package com.tracelink.appsec.module.awssecurity;

import java.time.Duration;
import org.springframework.stereotype.Service;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.sts.StsClient;

/** Read-only checks are available before activation; they do not prove service-role source access. */
@Service
public class AwsSecurityReadiness implements AutoCloseable {
    private final AwsSecuritySettings settings;
    private final AwsSecurityClientGateway gateway;
    private final AwsSecurityInputStore inputs;
    private final StsClient identity;
    @org.springframework.beans.factory.annotation.Autowired
    public AwsSecurityReadiness(AwsSecuritySettings settings, AwsSecurityClientGateway gateway, AwsSecurityInputStore inputs) {
        this(settings, gateway, inputs, StsClient.builder()
            .region(Region.of(settings.region().isBlank() ? "us-east-1" : settings.region()))
            .overrideConfiguration(c -> c.apiCallTimeout(Duration.ofSeconds(30)).apiCallAttemptTimeout(Duration.ofSeconds(15))).build());
    }
    AwsSecurityReadiness(AwsSecuritySettings settings, AwsSecurityClientGateway gateway, AwsSecurityInputStore inputs, StsClient identity) {
        this.settings=settings; this.gateway=gateway; this.inputs=inputs; this.identity=identity;
    }
    public record Check(String name, String state, String detail) {
        /** Keep existing API identifiers while using plain labels on the page. */
        public String label() { return switch(name) {
            case "Profile configuration" -> "AWS configuration";
            case "Runtime account" -> "AWS account";
            case "Input bucket encryption" -> "Encrypted code storage";
            case "Agent Space" -> "AWS scan workspace";
            case "Scanner module policy" -> "AWS scanner";
            case "Shared report storage" -> "Saved scan results";
            default -> name;
        }; }
    }
    public record Result(boolean ready, long verifiedAt, String reason, java.util.List<Check> checks, String runtimeArn) {
        public Result(boolean ready,long verifiedAt,String reason,java.util.List<Check> checks){this(ready,verifiedAt,reason,checks,null);}
        public Result(boolean ready,long verifiedAt,String reason){this(ready,verifiedAt,reason,java.util.List.of(),null);}
    }
    public Result check() {
        var checks=new java.util.ArrayList<Check>();
        String issue=settings.configurationIssue();
        checks.add(new Check("Profile configuration",issue==null?"VERIFIED":"FAILED",issue==null?"Profile fields are valid":issue));
        String failed=null,caller=null;
        if(issue==null) {
            try {
                var who=identity.getCallerIdentity(software.amazon.awssdk.services.sts.model.GetCallerIdentityRequest.builder().build());
                caller=who.arn();
                if(!settings.account().equals(who.account()))
                    failed="Watchtower is using a different AWS account from the one configured. Ask the deployment administrator to check the AWS account and role.";
            }catch(RuntimeException e){failed="Watchtower could not confirm its AWS account. Ask the deployment administrator to check AWS permissions and region.";}
        }
        checks.add(new Check("Runtime account",issue!=null?"NOT_CHECKED":failed==null?"VERIFIED":"FAILED",failed==null?(issue==null?"Account matches the configured profile":"Resolve profile configuration first"):failed));
        String bucket=null;
        if(issue==null&&failed==null)try{inputs.readiness(settings.profile());}catch(RuntimeException e){bucket="Watchtower could not verify encrypted code storage. Ask the deployment administrator to check the S3 bucket, permissions and region.";}
        checks.add(new Check("Input bucket encryption",issue!=null||failed!=null?"NOT_CHECKED":bucket==null?"VERIFIED":"FAILED",bucket==null?"Storage settings checked. Run a sample-code test to check that AWS can read the uploaded code.":bucket));
        String agent=null;
        if(issue==null&&failed==null&&bucket==null)try{gateway.readiness(settings.profile());}catch(RuntimeException e){agent="Watchtower could not access the AWS scan workspace (Agent Space). Ask the deployment administrator to check its permissions and region.";}
        checks.add(new Check("Agent Space",issue!=null||failed!=null||bucket!=null?"NOT_CHECKED":agent==null?"VERIFIED":"FAILED",agent==null?"Watchtower can access the configured AWS scan workspace.":agent));
        String problem=issue!=null?issue:failed!=null?failed:bucket!=null?bucket:agent;
        return new Result(problem==null,System.currentTimeMillis(),problem==null?
            "AWS connections work. Turn on AWS Security Agent in Scanner modules, include the Security review rule in its effective ruleset.":problem,java.util.List.copyOf(checks),caller);
    }
    public void close() { identity.close(); }
}
