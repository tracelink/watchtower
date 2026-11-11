package com.tracelink.appsec.module.awssecurity;

import java.util.*;
import com.tracelink.appsec.watchtower.core.auth.model.PrivilegeEntity;
import com.tracelink.appsec.watchtower.core.module.*;
import com.tracelink.appsec.watchtower.core.module.scanner.ICodeScanner;
import com.tracelink.appsec.watchtower.core.module.designer.IRuleDesigner;
import com.tracelink.appsec.watchtower.core.module.ruleeditor.*;
import com.tracelink.appsec.watchtower.core.rule.*;
import com.tracelink.appsec.watchtower.core.ruleset.*;

@WatchtowerModule
public class AwsSecurityModule extends AbstractCodeScanModule {
    public static final String NAME = "AwsSecurityAgent";
    public static final String ADMIN = "AWS Security Administration";
    public String getName() { return NAME; }
    public String getSchemaHistoryTable() { return "aws_security_schema_history"; }
    public String getMigrationsLocation() { return "db/awssecurity"; }
    @org.springframework.beans.factory.annotation.Autowired(required = false)
    private AwsSecuritySettings settings;

    public ICodeScanner getScanner() { return new AwsSecurityScanner(settings); }
    public IRuleDesigner getRuleDesigner() { return null; }
    public IRuleEditor getRuleEditor() {
        return new IRuleEditor() {
            public String getPrivilegeNameForAccess() { return ADMIN; }
            public RuleEditModelAndView getDefaultRuleEditModelAndView(RuleDto rule) {
                var view = new RuleEditModelAndView("rule-edit/awssecurity"); view.addObject("rule", rule); return view;
            }
        };
    }
    public List<PrivilegeEntity> getModulePrivileges() {
        return List.of(new PrivilegeEntity().setName(ADMIN).setCategory("Configuration")
                .setDescription("Manage AWS Security Agent repository controls and recovery."));
    }
    public List<RulesetDto> getProvidedRulesets() {
        var rule = new AwsSecurityRuleDto(); rule.setName("AWS Security Agent — security review"); rule.setPriority(RulePriority.HIGH);
        var ruleset = new RulesetDto(); ruleset.setName("Security review");
        ruleset.setDescription("Opt-in AWS assessment for pull requests and repositories. Requires approved source settings.");
        ruleset.setDesignation(RulesetDesignation.PROVIDED); ruleset.setRules(Set.of(rule));
        return List.of(ruleset);
    }
}
