package com.tracelink.appsec.watchtower.core.configuration;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import com.tracelink.appsec.watchtower.core.mvc.WatchtowerMvcHandler;
import com.tracelink.appsec.watchtower.core.sidebar.SidebarService;

/**
 * Configuration file to add the {@link WatchtowerMvcHandler} to the interceptors list
 * 
 * @author csmith
 *
 */
@Configuration
public class WatchtowerWebMvcConfig implements WebMvcConfigurer {

	private SidebarService sidebarService;

	public WatchtowerWebMvcConfig(@Autowired SidebarService sidebarService) {
		this.sidebarService = sidebarService;
	}

	@Override
	public void addInterceptors(InterceptorRegistry registry) {
		registry.addInterceptor(new WatchtowerMvcHandler(sidebarService));
	}
}
