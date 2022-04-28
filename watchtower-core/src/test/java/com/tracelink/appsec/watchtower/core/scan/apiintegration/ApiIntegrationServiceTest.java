package com.tracelink.appsec.watchtower.core.scan.apiintegration;

import org.hamcrest.MatcherAssert;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.BDDMockito;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.junit.jupiter.SpringExtension;

@ExtendWith(SpringExtension.class)
public class ApiIntegrationServiceTest {

	private ApiIntegrationService apiService;

	@MockBean
	private ApiIntegrationRepository apiRepo;
	@MockBean
	private PasswordEncoder passwordEncoder;

	@BeforeEach
	public void setup() {
		this.apiService = new ApiIntegrationService(apiRepo, passwordEncoder);
	}

	@Test
	public void testUpdate() throws ApiIntegrationException {
		ApiIntegrationEntity apiEntity = BDDMockito.mock(ApiIntegrationEntity.class);
		BDDMockito.when(apiEntity.getApiLabel()).thenReturn("test");
		apiService.save(apiEntity);
		BDDMockito.verify(apiRepo).saveAndFlush(BDDMockito.any());
	}

	@Test
	public void testUpdateBadLabel() {
		Assertions.assertThrows(IllegalArgumentException.class, () -> {
			ApiIntegrationEntity apiEntity = BDDMockito.mock(ApiIntegrationEntity.class);
			BDDMockito.when(apiEntity.getApiLabel()).thenReturn("test with spaces");
			apiService.save(apiEntity);
		});
	}

	@Test
	public void testDeleteExists() throws Exception {
		ApiIntegrationEntity entity = BDDMockito.mock(ApiIntegrationEntity.class);
		BDDMockito.when(entity.getApiLabel()).thenReturn("foo");
		BDDMockito.when(entity.getRegisterState()).thenReturn(RegisterState.NOT_REGISTERED);
		BDDMockito.when(apiRepo.findByApiLabel(BDDMockito.anyString())).thenReturn(entity);
		apiService.delete("foo");
		BDDMockito.verify(apiRepo).delete(entity);
		BDDMockito.verify(apiRepo).flush();
	}

	@Test
	public void testDeleteNotExists() throws Exception {
		BDDMockito.when(apiRepo.findByApiLabel(BDDMockito.anyString())).thenReturn(null);
		try {
			apiService.delete("foo");
		} catch (ApiIntegrationException e) {
			MatcherAssert.assertThat(e.getMessage(), Matchers.containsString("Unknown API"));
		}
	}

	@Test
	public void testDeleteBadState() throws Exception {
		ApiIntegrationEntity entity = BDDMockito.mock(ApiIntegrationEntity.class);
		BDDMockito.when(entity.getApiLabel()).thenReturn("foo");
		BDDMockito.when(entity.getRegisterState()).thenReturn(RegisterState.REGISTERED);
		BDDMockito.when(apiRepo.findByApiLabel(BDDMockito.anyString())).thenReturn(entity);
		try {
			apiService.delete("foo");
		} catch (ApiIntegrationException e) {
			MatcherAssert.assertThat(e.getMessage(),
					Matchers.containsString("API integration cannot be deleted in state"));
		}
	}

	@Test
	public void testGetAll() {
		apiService.getAllSettings();
		BDDMockito.verify(apiRepo).findAll();
	}
}
