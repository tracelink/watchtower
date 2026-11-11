package com.tracelink.appsec.module.awssecurity;

import jakarta.annotation.PostConstruct;
import org.springframework.stereotype.Component;
import com.tracelink.appsec.watchtower.core.sidebar.SidebarLink;
import com.tracelink.appsec.watchtower.core.sidebar.SidebarService;

/** Register setup only when the optional module is installed, with the same route permissions. */
@Component
public class AwsSecurityNavigation {
 private final SidebarService sidebar;
 public AwsSecurityNavigation(SidebarService sidebar){this.sidebar=sidebar;}
 @PostConstruct public void register(){sidebar.addLink("Configuration",new SidebarLink().setDisplayName("AWS Security Agent").setMaterialIcon("cloud").setUrl("/aws-security/readiness/view").setAuthorizationExpression("hasAuthority('AWS Security Administration') and hasAuthority('Repository Settings View')"));}
}
