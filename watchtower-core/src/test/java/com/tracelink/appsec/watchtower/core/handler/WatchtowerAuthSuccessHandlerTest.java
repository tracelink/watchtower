package com.tracelink.appsec.watchtower.core.handler;

import java.util.Date;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.BDDMockito;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.security.authentication.event.InteractiveAuthenticationSuccessEvent;
import org.springframework.security.core.Authentication;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import com.tracelink.appsec.watchtower.core.auth.model.UserEntity;
import com.tracelink.appsec.watchtower.core.auth.service.UserService;

@ExtendWith(SpringExtension.class)
@SpringBootTest
@ActiveProfiles("dev")
public class WatchtowerAuthSuccessHandlerTest {
    @MockBean
    UserService mockUserService;

    @MockBean
    Authentication mockAuth;

    @Test
    public void testOnApplicationEvent() throws Exception {
        WatchtowerAuthSuccessHandler authSuccessHandler = new WatchtowerAuthSuccessHandler(mockUserService);
        UserEntity user = new UserEntity();
        InteractiveAuthenticationSuccessEvent event = new InteractiveAuthenticationSuccessEvent(mockAuth, WatchtowerAuthSuccessHandler.class);

        BDDMockito.when(event.getAuthentication().getName()).thenReturn("user1");
        BDDMockito.when(mockUserService.findByUsername("user1")).thenReturn(user);

        Date oldLogin = user.getLastLogin();
        authSuccessHandler.onApplicationEvent(event);
        Date newLogin = user.getLastLogin();

        Assertions.assertEquals(oldLogin,null);
        Assertions.assertNotEquals(oldLogin,newLogin);
    }
}
