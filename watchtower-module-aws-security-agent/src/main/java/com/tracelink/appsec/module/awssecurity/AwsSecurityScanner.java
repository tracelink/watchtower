package com.tracelink.appsec.module.awssecurity;

import java.util.*;
import com.tracelink.appsec.watchtower.core.module.scanner.*;
import com.tracelink.appsec.watchtower.core.rule.RuleDto;
import com.tracelink.appsec.watchtower.core.scan.code.*;
import com.tracelink.appsec.watchtower.core.scan.code.report.*;

/** Descriptor only. The durable service owns all network submission. */
public final class AwsSecurityScanner implements ICodeScanner {
    private final AwsSecuritySettings settings;

    public AwsSecurityScanner() { this(null); }
    public AwsSecurityScanner(AwsSecuritySettings settings) { this.settings = settings; }

    /** Disabled submission, unpassed gates or an incomplete profile; read from settings only. */
    @Override
    public String setupIssue() { return settings == null ? null : settings.unavailable(); }
    public ExecutionCapability getExecutionCapability() { return ExecutionCapability.REMOTE_SERVICE; }
    public boolean supportsScanType(CodeScanType type) { return type == CodeScanType.PULL_REQUEST || type == CodeScanType.REPOSITORY; }
    public ScanScope getRequiredScope() { return ScanScope.FULL_SOURCE; }
    public Set<String> getExcludedFolders() { return Set.of(".git", "node_modules", "target", "build", "vendor"); }
    public List<Class<? extends RuleDto>> getSupportedRuleClass() { return List.of(AwsSecurityRuleDto.class); }
    public CodeScanReport scan(CodeScanConfig config) {
        var result = new CodeScanReport();
        result.addError(new CodeScanError("AWS Security Agent requires durable PR/repository dispatch; test, shadow, upload and CLI execution are unsupported"));
        return result;
    }
}
