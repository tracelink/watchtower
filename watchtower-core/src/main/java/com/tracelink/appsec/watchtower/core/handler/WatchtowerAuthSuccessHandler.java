package com.tracelink.appsec.watchtower.core.handler;

import java.util.Date;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationListener;
import org.springframework.security.authentication.event.InteractiveAuthenticationSuccessEvent;
import org.springframework.stereotype.Component;

import com.tracelink.appsec.watchtower.core.auth.model.UserEntity;
import com.tracelink.appsec.watchtower.core.auth.service.UserService;

/**
 * Listens for successful login event to set user data
 *
 * @author bhoran
 */

@Component
public class WatchtowerAuthSuccessHandler
		implements ApplicationListener<InteractiveAuthenticationSuccessEvent> {

	private UserService userService;

	public WatchtowerAuthSuccessHandler(@Autowired UserService userService) {
		this.userService = userService;
	}

	@Override
	public void onApplicationEvent(InteractiveAuthenticationSuccessEvent event) {
		String username = event.getAuthentication().getName();
		UserEntity user = userService.findByUsername(username);

		user.setLastLogin(new Date());
		userService.updateUser(user);
	}
}
