package com.tracelink.appsec.watchtower.core.encryption.controller;

import static org.mockito.Mockito.times;

import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.Collections;

import org.hamcrest.Matchers;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.BDDMockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;

import com.tracelink.appsec.watchtower.core.WatchtowerTestApplication;
import com.tracelink.appsec.watchtower.core.auth.model.CorePrivilege;
import com.tracelink.appsec.watchtower.core.encryption.model.DataEncryptionKey;
import com.tracelink.appsec.watchtower.core.encryption.model.EncryptionMetadata;
import com.tracelink.appsec.watchtower.core.encryption.service.KeyRotationService;
import com.tracelink.appsec.watchtower.core.encryption.utils.EncryptionUtils;
import com.tracelink.appsec.watchtower.core.mvc.WatchtowerModelAndView;

@ExtendWith(SpringExtension.class)
@SpringBootTest(classes = WatchtowerTestApplication.class)
@AutoConfigureMockMvc
public class EncryptionMgmtControllerTest {

	@Autowired
	private MockMvc mockMvc;

	@MockBean
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

		mockMvc.perform(MockMvcRequestBuilders.get("/encryption"))
				.andExpect(MockMvcResultMatchers.status().isOk())
				.andExpect(MockMvcResultMatchers.model()
						.attribute("contentViewName", "admin/encryption"))
				.andExpect(MockMvcResultMatchers.model()
						.attribute("scripts", Matchers.contains("/scripts/encryption.js")))
				.andExpect(MockMvcResultMatchers.model()
						.attribute("deks", Matchers.contains(dataEncryptionKey)))
				.andExpect(MockMvcResultMatchers.model().attribute("metadata", encryptionMetadata));
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

		BDDMockito.verify(keyRotationService, times(1)).rotateKeys();
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

		BDDMockito.verify(keyRotationService, times(1)).rotateKey(1L);
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
