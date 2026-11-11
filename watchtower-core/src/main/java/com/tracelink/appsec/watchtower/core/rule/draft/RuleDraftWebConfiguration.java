package com.tracelink.appsec.watchtower.core.rule.draft;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/** Lets a drafted rule follow its save in whichever designer the module provides, without the modules knowing. */
@Configuration
public class RuleDraftWebConfiguration implements WebMvcConfigurer {
	private final RuleDraftSaveHook hook;
	private final RuleDraftService drafts;

	public RuleDraftWebConfiguration(RuleDraftSaveHook hook, RuleDraftService drafts) {
		this.hook = hook;
		this.drafts = drafts;
	}

	@Override
	public void addInterceptors(InterceptorRegistry registry) {
		registry.addInterceptor(new RuleDraftSaveInterceptor(hook, drafts)).addPathPatterns("/designer/*/save");
	}
}
