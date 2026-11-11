package com.tracelink.appsec.watchtower.core.configuration;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Lazy;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import com.tracelink.appsec.watchtower.core.auth.model.UserEntity;
import com.tracelink.appsec.watchtower.core.auth.service.UserService;
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

	private String appVersion;

	private final UserService userService;

	public WatchtowerWebMvcConfig(@Autowired SidebarService sidebarService,
			@Value("${APP_VERSION:local}") String appVersion, @Lazy UserService userService) {
		this.sidebarService = sidebarService;
		this.appVersion = appVersion;
		this.userService = userService;
	}

	@Override
	public void addInterceptors(InterceptorRegistry registry) {
		registry.addInterceptor(new WatchtowerMvcHandler(sidebarService, appVersion, username -> {
			UserEntity user = userService.findByUsername(username);
			return user == null ? null : user.getRolesString();
		}));
	}
}
