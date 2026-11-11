package com.tracelink.appsec.watchtower.core.rule.workflow;

import static org.assertj.core.api.Assertions.assertThat;

import java.net.URI;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.BDDMockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;
import org.springframework.web.util.UriComponentsBuilder;

import com.tracelink.appsec.watchtower.core.WatchtowerTestApplication;
import com.tracelink.appsec.watchtower.core.auth.model.CorePrivilege;
import com.tracelink.appsec.watchtower.core.rule.RuleService;
import com.tracelink.appsec.watchtower.core.scan.presentation.ScannerIdentity;

/**
 * After saving the Setup gaps bulk form the person goes back to the same list. The redirect is always
 * {@code /rules/work} on this site: every value on it comes from a known list or is encoded as plain query text,
 * and a value that is not on the list is refused instead of being passed along.
 */
@ExtendWith(SpringExtension.class)
@SpringBootTest(classes = WatchtowerTestApplication.class)
@AutoConfigureMockMvc
class RuleWorkSetupRedirectTest {
	@Autowired
	private MockMvc mockMvc;
	@MockitoBean
	private RuleService rules;
	@MockitoBean
	private RuleWorkService work;

	private MockHttpServletRequestBuilder save() {
		BDDMockito.when(work.scanners()).thenReturn(Map.of("pmd", ScannerIdentity.of("pmd")));
		return MockMvcRequestBuilders.post("/rules/work/setup").param("ruleId", "7").param("owner", "appsec")
				.with(SecurityMockMvcRequestPostProcessors.csrf());
	}

	private URI redirectOf(MockHttpServletRequestBuilder request) throws Exception {
		String location = mockMvc.perform(request).andExpect(MockMvcResultMatchers.status().is3xxRedirection()).andReturn()
				.getResponse().getRedirectedUrl();
		return URI.create(location);
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.RULE_MODIFY_NAME})
	void savingGoesBackToTheSameListOnThisSite() throws Exception {
		URI back = redirectOf(save().param("gap", "cwe").param("scanner", "pmd").param("days", "90").param("pageSize", "50")
				.param("search", "sql"));

		assertThat(back.getScheme()).isNull();
		assertThat(back.getHost()).isNull();
		assertThat(back.getPath()).isEqualTo("/rules/work");
		var query = UriComponentsBuilder.fromUri(back).build().getQueryParams();
		assertThat(query.getFirst("queue")).isEqualTo("setup");
		assertThat(query.getFirst("gap")).isEqualTo("cwe");
		assertThat(query.getFirst("scanner")).isEqualTo("pmd");
		assertThat(query.getFirst("days")).isEqualTo("90");
		assertThat(query.getFirst("pageSize")).isEqualTo("50");
		assertThat(query.getFirst("search")).isEqualTo("sql");
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.RULE_MODIFY_NAME})
	void searchTextThatLooksLikeAnAddressStaysPlainEncodedText() throws Exception {
		String hostile = "//evil.example/x?next=https://evil.example&a=b#frag";

		URI back = redirectOf(save().param("search", hostile));

		assertThat(back.getHost()).isNull();
		assertThat(back.getPath()).isEqualTo("/rules/work");
		assertThat(back.getFragment()).isNull();
		var query = UriComponentsBuilder.fromUri(back).build().getQueryParams();
		assertThat(java.net.URLDecoder.decode(query.getFirst("search"), java.nio.charset.StandardCharsets.UTF_8)).isEqualTo(hostile);
		assertThat(query.keySet()).doesNotContain("next", "a");
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.RULE_MODIFY_NAME})
	void aValueThatIsNotOnTheListIsRefusedNotPassedAlong() throws Exception {
		for (MockHttpServletRequestBuilder bad : new MockHttpServletRequestBuilder[] { save().param("gap", "https://evil.example"),
				save().param("days", "31"), save().param("scanner", "//evil.example"), save().param("scanner", "unknown"),
				save().param("pageSize", "1000") }) {
			mockMvc.perform(bad).andExpect(MockMvcResultMatchers.status().isBadRequest());
		}
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.RULE_MODIFY_NAME})
	void withNoOptionsTheListOpensOnItsDefaults() throws Exception {
		URI back = redirectOf(save());

		var query = UriComponentsBuilder.fromUri(back).build().getQueryParams();
		assertThat(back.getPath()).isEqualTo("/rules/work");
		assertThat(query.getFirst("queue")).isEqualTo("setup");
		assertThat(query.getFirst("gap")).isEqualTo("all");
		assertThat(query.getFirst("scanner")).isEqualTo("all");
		assertThat(query.getFirst("days")).isEqualTo("30");
	}
}
