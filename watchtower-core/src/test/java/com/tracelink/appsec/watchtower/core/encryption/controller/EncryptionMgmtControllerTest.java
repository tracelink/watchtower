package com.tracelink.appsec.watchtower.core.encryption.controller;

import static org.mockito.Mockito.times;
import static org.mockito.Mockito.timeout;

import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.Collections;

import org.hamcrest.Matchers;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.BDDMockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;

import com.tracelink.appsec.watchtower.core.WatchtowerTestApplication;
import com.tracelink.appsec.watchtower.core.auth.model.CorePrivilege;
import com.tracelink.appsec.watchtower.core.encryption.model.DataEncryptionKey;
import com.tracelink.appsec.watchtower.core.encryption.model.EncryptionMetadata;
import com.tracelink.appsec.watchtower.core.encryption.service.KeyRotationService;
import com.tracelink.appsec.watchtower.core.encryption.utils.EncryptionUtils;
import com.tracelink.appsec.watchtower.core.mvc.WatchtowerModelAndView;
import com.tracelink.appsec.watchtower.core.ui.HtmlAssertions;

@ExtendWith(SpringExtension.class)
@SpringBootTest(classes = WatchtowerTestApplication.class)
@AutoConfigureMockMvc
public class EncryptionMgmtControllerTest {

	@Autowired
	private MockMvc mockMvc;

	@MockitoBean
	private KeyRotationService keyRotationService;

	private DataEncryptionKey dataEncryptionKey;
	private EncryptionMetadata encryptionMetadata;

	@BeforeEach
	public void init() {
		dataEncryptionKey = new DataEncryptionKey();
		dataEncryptionKey.setCurrentKey(EncryptionUtils.generateKey());
		dataEncryptionKey.setLastRotationDateTime(LocalDateTime.now().minusWeeks(2));

		encryptionMetadata = new EncryptionMetadata();
		encryptionMetadata.setRotationScheduleEnabled(true);
		encryptionMetadata.setRotationPeriod(90);
		encryptionMetadata.setLastRotationDateTime(LocalDateTime.now().minus(4, ChronoUnit.MONTHS));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.ENCRYPTION_VIEW_NAME})
	public void testGetEncryptionMgmt() throws Exception {
		BDDMockito.when(keyRotationService.getKeys())
				.thenReturn(Collections.singletonList(dataEncryptionKey));
		BDDMockito.when(keyRotationService.getEncryptionMetadata())
				.thenReturn(encryptionMetadata);

		MvcResult result = mockMvc.perform(MockMvcRequestBuilders.get("/encryption"))
				.andExpect(MockMvcResultMatchers.status().isOk())
				.andExpect(MockMvcResultMatchers.model()
						.attribute("contentViewName", "admin/encryption"))
				.andExpect(MockMvcResultMatchers.model()
						.attribute("scripts", Matchers.contains("/scripts/encryption.js")))
				.andExpect(MockMvcResultMatchers.model()
						.attribute("deks", Matchers.contains(dataEncryptionKey)))
				.andExpect(MockMvcResultMatchers.model().attribute("metadata", encryptionMetadata))
				.andExpect(MockMvcResultMatchers.model().attribute("encryptionOn", false))
				.andExpect(MockMvcResultMatchers.content()
						.string(Matchers.containsString("Encryption off")))
				.andReturn();
		// admin/encryption.html had form-row, form-inline and close-button conversions in
		// Phase 11 Section B - guard the result structurally.
		HtmlAssertions.assertHtmlIntegrity(result);
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.ENCRYPTION_MODIFY_NAME})
	public void testRotateKeys() throws Exception {
		mockMvc.perform(MockMvcRequestBuilders.post("/encryption/rotate")
				.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.status().is3xxRedirection())
				.andExpect(MockMvcResultMatchers.redirectedUrl("/encryption"))
				.andExpect(MockMvcResultMatchers.flash()
						.attribute(WatchtowerModelAndView.SUCCESS_NOTIFICATION,
								"Key rotation in progress"));

		BDDMockito.verify(keyRotationService, timeout(5000).times(1)).rotateKeys();
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.ENCRYPTION_MODIFY_NAME})
	public void testRotateKeysSingleKey() throws Exception {
		mockMvc.perform(MockMvcRequestBuilders.post("/encryption/rotate").param("keyId", "1")
				.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.status().is3xxRedirection())
				.andExpect(MockMvcResultMatchers.redirectedUrl("/encryption"))
				.andExpect(MockMvcResultMatchers.flash()
						.attribute(WatchtowerModelAndView.SUCCESS_NOTIFICATION,
								"Key rotation in progress"));

		BDDMockito.verify(keyRotationService, timeout(5000).times(1)).rotateKey(1L);
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.ENCRYPTION_MODIFY_NAME})
	public void testEnableRotationScheduleSuccess() throws Exception {
		mockMvc.perform(MockMvcRequestBuilders.post("/encryption/rotate/schedule")
				.param("enable", "false").with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.status().is3xxRedirection())
				.andExpect(MockMvcResultMatchers.redirectedUrl("/encryption"))
				.andExpect(MockMvcResultMatchers.flash()
						.attribute(WatchtowerModelAndView.SUCCESS_NOTIFICATION,
								"Successfully disabled rotation schedule"));

		BDDMockito.verify(keyRotationService, times(1)).enableRotationSchedule(false, null);
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.ENCRYPTION_MODIFY_NAME})
	public void testEnableRotationScheduleWithPeriod() throws Exception {
		mockMvc.perform(MockMvcRequestBuilders.post("/encryption/rotate/schedule")
				.param("enable", "true").param("rotationPeriod", "120")
				.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.status().is3xxRedirection())
				.andExpect(MockMvcResultMatchers.redirectedUrl("/encryption"))
				.andExpect(MockMvcResultMatchers.flash()
						.attribute(WatchtowerModelAndView.SUCCESS_NOTIFICATION,
								"Successfully updated rotation schedule"));

		BDDMockito.verify(keyRotationService, times(1)).enableRotationSchedule(true, 120);
	}

	@Test
	@WithMockUser(username = "keyadmin", authorities = {CorePrivilege.ENCRYPTION_MODIFY_NAME})
	public void testScheduleChangeRecordsWhoMadeIt() throws Exception {
		ch.qos.logback.classic.Logger controllerLogger = (ch.qos.logback.classic.Logger) org.slf4j.LoggerFactory
				.getLogger(EncryptionMgmtController.class);
		ch.qos.logback.core.read.ListAppender<ch.qos.logback.classic.spi.ILoggingEvent> appender =
				new ch.qos.logback.core.read.ListAppender<>();
		appender.start();
		controllerLogger.addAppender(appender);
		try {
			mockMvc.perform(MockMvcRequestBuilders.post("/encryption/rotate/schedule")
					.param("enable", "true").param("rotationPeriod", "45")
					.with(SecurityMockMvcRequestPostProcessors.csrf()))
					.andExpect(MockMvcResultMatchers.status().is3xxRedirection());
			mockMvc.perform(MockMvcRequestBuilders.post("/encryption/rotate")
					.with(SecurityMockMvcRequestPostProcessors.csrf()))
					.andExpect(MockMvcResultMatchers.status().is3xxRedirection());

			java.util.List<String> messages = appender.list.stream()
					.map(ch.qos.logback.classic.spi.ILoggingEvent::getFormattedMessage).toList();
			org.junit.jupiter.api.Assertions.assertTrue(
					messages.stream().anyMatch(m -> m.contains("keyadmin") && m.contains("45")),
					"the log must say who set the schedule and its period: " + messages);
			org.junit.jupiter.api.Assertions.assertTrue(
					messages.stream().anyMatch(m -> m.contains("keyadmin") && m.contains("rotat")),
					"the log must say who started a rotation: " + messages);
		} finally {
			controllerLogger.detachAppender(appender);
		}
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.ENCRYPTION_MODIFY_NAME})
	public void testEnableRotationScheduleFailure() throws Exception {
		BDDMockito.doThrow(new IllegalArgumentException("Invalid")).when(keyRotationService)
				.enableRotationSchedule(true, null);

		mockMvc.perform(MockMvcRequestBuilders.post("/encryption/rotate/schedule")
				.param("enable", "true").with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.status().is3xxRedirection())
				.andExpect(MockMvcResultMatchers.redirectedUrl("/encryption"))
				.andExpect(MockMvcResultMatchers.flash()
						.attribute(WatchtowerModelAndView.FAILURE_NOTIFICATION, "Invalid"));

		BDDMockito.verify(keyRotationService, times(1)).enableRotationSchedule(true, null);
	}
}
