package com.tracelink.appsec.watchtower.core.configuration;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.BDDMockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;

import com.tracelink.appsec.watchtower.core.WatchtowerTestApplication;
import com.tracelink.appsec.watchtower.core.auth.model.CorePrivilege;
import com.tracelink.appsec.watchtower.core.auth.model.UserEntity;
import com.tracelink.appsec.watchtower.core.auth.service.ApiUserService;
import com.tracelink.appsec.watchtower.core.auth.service.UserService;

/**
 * Verifies that {@linkplain UISecurityConfig} and {@linkplain RestSecurityConfig} each
 * authenticate against their own {@linkplain org.springframework.security.core.userdetails.UserDetailsService}
 * and not the other's. A misconfigured {@code SecurityFilterChain} (e.g. one global
 * {@code UserDetailsService} bean picked up by both chains) would let a REST-only credential
 * (an API key id/secret) log into the UI, or a UI username/password authenticate over REST basic
 * auth - neither of which produces a compile error, so this is exercised end to end rather than
 * unit tested against the config classes directly.
 */
@ExtendWith(SpringExtension.class)
@SpringBootTest(classes = WatchtowerTestApplication.class)
@AutoConfigureMockMvc
public class SecurityFilterChainWiringTest {

	private static final String UI_USERNAME = "uiuser";
	private static final String UI_PASSWORD = "uipass";
	private static final String API_KEY_ID = "apikeyid";
	private static final String API_SECRET = "apisecret";

	@Autowired
	private MockMvc mockMvc;

	@Autowired
	private PasswordEncoder passwordEncoder;

	@MockitoBean
	private UserService mockUserService;

	@MockitoBean
	private ApiUserService mockApiUserService;

 @Test void publicFontsAreBinaryWhileApplicationPagesStayProtected() throws Exception {
  var response=mockMvc.perform(MockMvcRequestBuilders.get("/fonts/Inter-latin-variable.woff2"))
   .andExpect(MockMvcResultMatchers.status().isOk()).andReturn().getResponse();
  org.junit.jupiter.api.Assertions.assertTrue(response.getContentType().contains("font"));
  org.junit.jupiter.api.Assertions.assertArrayEquals(new byte[]{'w','O','F','2'},java.util.Arrays.copyOf(response.getContentAsByteArray(),4));
  mockMvc.perform(MockMvcRequestBuilders.get("/usermgmt")).andExpect(MockMvcResultMatchers.status().is3xxRedirection());
 }

	private void stubUiUser() {
		UserDetails uiUser = User.builder().username(UI_USERNAME)
				.password(passwordEncoder.encode(UI_PASSWORD)).authorities("USER").build();
		BDDMockito.when(mockUserService.loadUserByUsername(UI_USERNAME)).thenReturn(uiUser);
		BDDMockito.when(mockUserService.findByUsername(UI_USERNAME))
				.thenReturn(new UserEntity());
	}

	private void stubApiKeyUser() {
		UserDetails apiUser = User.builder().username(API_KEY_ID)
				.password(passwordEncoder.encode(API_SECRET))
				.authorities(CorePrivilege.SCAN_DASHBOARDS_NAME).build();
		BDDMockito.when(mockApiUserService.loadUserByUsername(API_KEY_ID)).thenReturn(apiUser);
	}

	@Test
	public void testUiLoginAcceptsUiCredential() throws Exception {
		stubUiUser();

		mockMvc.perform(MockMvcRequestBuilders.post("/login")
				.param("username", UI_USERNAME).param("password", UI_PASSWORD)
				.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.status().is3xxRedirection())
				.andExpect(MockMvcResultMatchers.redirectedUrl("/"));
	}

	@Test
	public void testUiLoginRejectsApiKeyCredential() throws Exception {
		stubApiKeyUser();
		BDDMockito.when(mockUserService.loadUserByUsername(API_KEY_ID))
				.thenThrow(new UsernameNotFoundException("Unknown username"));

		mockMvc.perform(MockMvcRequestBuilders.post("/login")
				.param("username", API_KEY_ID).param("password", API_SECRET)
				.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.status().is3xxRedirection())
				.andExpect(MockMvcResultMatchers.redirectedUrlPattern("/login?error=*"));
	}

	@Test
	public void testRestBasicAuthAcceptsApiKeyCredential() throws Exception {
		stubApiKeyUser();

		mockMvc.perform(MockMvcRequestBuilders.get("/rest/metrics/periods")
				.with(SecurityMockMvcRequestPostProcessors.httpBasic(API_KEY_ID, API_SECRET)))
				.andExpect(MockMvcResultMatchers.status().isOk());
	}

	@Test
	public void testRestBasicAuthRejectsUiCredential() throws Exception {
		stubUiUser();
		BDDMockito.when(mockApiUserService.loadUserByUsername(UI_USERNAME))
				.thenThrow(new UsernameNotFoundException("Unknown Api Key"));

		mockMvc.perform(MockMvcRequestBuilders.get("/rest/metrics/periods")
				.with(SecurityMockMvcRequestPostProcessors.httpBasic(UI_USERNAME, UI_PASSWORD)))
				.andExpect(MockMvcResultMatchers.status().isUnauthorized());
	}

	private void stubScanSubmitApiKeyUser() {
		UserDetails apiUser = User.builder().username(API_KEY_ID)
				.password(passwordEncoder.encode(API_SECRET))
				.authorities(CorePrivilege.SCAN_SUBMIT_NAME).build();
		BDDMockito.when(mockApiUserService.loadUserByUsername(API_KEY_ID)).thenReturn(apiUser);
	}

	/**
	 * The status of the request, or {@code -1} when it got past every security filter and the
	 * controller itself failed (these requests carry no upload, so the controller cannot succeed).
	 */
	private int statusOrReachedController(
			org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder request)
			throws Exception {
		try {
			return mockMvc.perform(request).andReturn().getResponse().getStatus();
		} catch (jakarta.servlet.ServletException reachedTheController) {
			return -1;
		}
	}

	private static org.springframework.test.web.servlet.request.RequestPostProcessor sessionUserWithScanSubmit() {
		return SecurityMockMvcRequestPostProcessors.user("sessionuser").authorities(
				new org.springframework.security.core.authority.SimpleGrantedAuthority(
						CorePrivilege.SCAN_SUBMIT_NAME));
	}

	@Test
	public void testRestScanSubmissionFromABrowserSessionNeedsACsrfToken() throws Exception {
		org.junit.jupiter.api.Assertions.assertEquals(403, statusOrReachedController(
				MockMvcRequestBuilders.post("/rest/uploadscan").with(sessionUserWithScanSubmit())));
		org.junit.jupiter.api.Assertions.assertEquals(403, statusOrReachedController(
				MockMvcRequestBuilders.post("/rest/reposcan").with(sessionUserWithScanSubmit())));
	}

	@Test
	public void testRestScanSubmissionFromABrowserSessionWithACsrfTokenIsNotRefused() throws Exception {
		org.junit.jupiter.api.Assertions.assertNotEquals(403,
				statusOrReachedController(MockMvcRequestBuilders.post("/rest/uploadscan")
						.with(sessionUserWithScanSubmit())
						.with(SecurityMockMvcRequestPostProcessors.csrf())));
	}

	@Test
	public void testRestScanSubmissionWithBasicAuthNeedsNoCsrfToken() throws Exception {
		stubScanSubmitApiKeyUser();

		org.junit.jupiter.api.Assertions.assertNotEquals(403,
				statusOrReachedController(MockMvcRequestBuilders.post("/rest/uploadscan")
						.with(SecurityMockMvcRequestPostProcessors.httpBasic(API_KEY_ID, API_SECRET))));
	}

	@Test
	public void testSignedWebhookAndCspReportNeedNoCsrfToken() throws Exception {
		org.junit.jupiter.api.Assertions.assertNotEquals(403, statusOrReachedController(
				MockMvcRequestBuilders.post("/rest/scan/anyintegration").content("{}")));
		org.junit.jupiter.api.Assertions.assertNotEquals(403, statusOrReachedController(
				MockMvcRequestBuilders.post("/rest/csp/report").content("{}")));
	}

	@Test
	public void testActuatorHealthIsReachableWithoutAuthentication() throws Exception {
		// The management port's security boundary is network isolation (loopback bind,
		// never exposed via the Service/Ingress - see application.yaml), not app-level
		// auth: this app has no separate management-context security config, so without
		// an explicit permitAll here, UISecurityConfig's catch-all
		// anyRequest().authenticated() would 302-redirect a Prometheus scraper or a
		// plain curl from a kubectl port-forward to /login instead of returning metrics.
		mockMvc.perform(MockMvcRequestBuilders.get("/actuator/health"))
				.andExpect(MockMvcResultMatchers.status().isOk());
	}

}
