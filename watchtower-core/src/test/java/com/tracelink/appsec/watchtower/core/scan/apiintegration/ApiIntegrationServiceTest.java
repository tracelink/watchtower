package com.tracelink.appsec.watchtower.core.scan.apiintegration;

import java.util.Optional;

import org.hamcrest.MatcherAssert;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.BDDMockito;
import org.mockito.Mockito;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import com.tracelink.appsec.watchtower.core.scan.IWatchtowerApi;

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
	public void testUpdate() {
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

	@Test
	public void testUpsertEntity() {
		ApiIntegrationEntity integrationEntity = BDDMockito.mock(ApiIntegrationEntity.class);
		BDDMockito.when(integrationEntity.getApiLabel()).thenReturn("myIntegration");
		BDDMockito.when(integrationEntity.getIntegrationId()).thenReturn(1L);
		BDDMockito.when(apiRepo.findByApiLabel(BDDMockito.anyString()))
				.thenReturn(integrationEntity);

		apiService.upsertEntity(integrationEntity);
		BDDMockito.verify(apiRepo).saveAndFlush(integrationEntity);
	}

	@Test
	public void testUpsertEntityNew() {
		ApiIntegrationEntity integrationEntity = BDDMockito.mock(ApiIntegrationEntity.class);
		BDDMockito.when(integrationEntity.getApiLabel()).thenReturn("myIntegration");
		BDDMockito.when(apiRepo.findByApiLabel(BDDMockito.anyString())).thenReturn(null);

		apiService.upsertEntity(integrationEntity);
		BDDMockito.verify(apiRepo).saveAndFlush(integrationEntity);
	}

	@Test
	public void testUpsertEntityExistingApiLabel() {
		ApiIntegrationEntity integrationEntity = BDDMockito.mock(ApiIntegrationEntity.class);
		BDDMockito.when(integrationEntity.getApiLabel()).thenReturn("myIntegration");
		BDDMockito.when(integrationEntity.getIntegrationId()).thenReturn(2L);

		ApiIntegrationEntity savedEntity = BDDMockito.mock(ApiIntegrationEntity.class);
		BDDMockito.when(savedEntity.getApiLabel()).thenReturn("myIntegration");
		BDDMockito.when(savedEntity.getIntegrationId()).thenReturn(1L);
		BDDMockito.when(apiRepo.findByApiLabel(BDDMockito.anyString()))
				.thenReturn(savedEntity);
		try {
			apiService.upsertEntity(integrationEntity);
			MatcherAssert.assertThat("Exception not thrown", false);
		} catch (IllegalArgumentException e) {
			MatcherAssert.assertThat(e.getMessage(),
					Matchers.is("There is already an API integration with this label"));
		}
		BDDMockito.verify(apiRepo, Mockito.times(0)).saveAndFlush(integrationEntity);
	}

	@Test
	public void testFindById() {
		ApiIntegrationEntity integrationEntity = BDDMockito.mock(ApiIntegrationEntity.class);
		BDDMockito.when(apiRepo.findById(1L)).thenReturn(Optional.of(integrationEntity));
		MatcherAssert.assertThat(apiService.findById(1L), Matchers.is(integrationEntity));
		BDDMockito.verify(apiRepo).findById(1L);
	}

	@Test
	public void testFindByIdNull() {
		BDDMockito.when(apiRepo.findById(1L)).thenReturn(Optional.empty());
		MatcherAssert.assertThat(apiService.findById(1L), Matchers.nullValue());
		BDDMockito.verify(apiRepo).findById(1L);
	}

	@Test
	public void testRegister() throws Exception {
		IWatchtowerApi api = BDDMockito.mock(IWatchtowerApi.class);
		ApiIntegrationEntity integrationEntity = BDDMockito.mock(ApiIntegrationEntity.class);
		BDDMockito.when(integrationEntity.getApiLabel()).thenReturn("myIntegration");
		BDDMockito.when(integrationEntity.getIntegrationId()).thenReturn(1L);
		BDDMockito.when(integrationEntity.getRegisterState())
				.thenReturn(RegisterState.NOT_REGISTERED);
		BDDMockito.when(integrationEntity.createApi()).thenReturn(api);

		BDDMockito.when(apiRepo.findByApiLabel("myIntegration")).thenReturn(integrationEntity);

		apiService.register("myIntegration").get();

		BDDMockito.verify(integrationEntity).setRegisterState(RegisterState.IN_PROGRESS);
		BDDMockito.verify(apiRepo, BDDMockito.times(2)).saveAndFlush(integrationEntity);
		BDDMockito.verify(api).register(passwordEncoder);
	}

	@Test
	public void testRegisterFailure() throws Exception {
		IWatchtowerApi api = BDDMockito.mock(IWatchtowerApi.class);
		BDDMockito.doThrow(new IllegalArgumentException("Bad registration")).when(api)
				.register(passwordEncoder);
		ApiIntegrationEntity integrationEntity = BDDMockito.mock(ApiIntegrationEntity.class);
		BDDMockito.when(integrationEntity.getApiLabel()).thenReturn("myIntegration");
		BDDMockito.when(integrationEntity.getIntegrationId()).thenReturn(1L);
		BDDMockito.when(integrationEntity.getRegisterState())
				.thenReturn(RegisterState.NOT_REGISTERED);
		BDDMockito.when(integrationEntity.createApi()).thenReturn(api);

		BDDMockito.when(apiRepo.findByApiLabel("myIntegration")).thenReturn(integrationEntity);

		apiService.register("myIntegration");

		BDDMockito.verify(integrationEntity).setRegisterState(RegisterState.IN_PROGRESS);
		BDDMockito.verify(apiRepo).saveAndFlush(integrationEntity);
		BDDMockito.verify(api).register(passwordEncoder);
	}

	@Test
	public void testRegisterUnknownApiLabel() {
		try {
			apiService.register("myIntegration");
			MatcherAssert.assertThat("Exception not thrown", false);
		} catch (ApiIntegrationException e) {
			MatcherAssert.assertThat(e.getMessage(), Matchers.is("Unknown API integration label"));
		}

		BDDMockito.verify(apiRepo, Mockito.times(0)).saveAndFlush(BDDMockito.any());
	}

	@Test
	public void testRegisterInvalidState() {
		ApiIntegrationEntity integrationEntity = BDDMockito.mock(ApiIntegrationEntity.class);
		BDDMockito.when(integrationEntity.getApiLabel()).thenReturn("myIntegration");
		BDDMockito.when(integrationEntity.getIntegrationId()).thenReturn(1L);
		BDDMockito.when(integrationEntity.getRegisterState())
				.thenReturn(RegisterState.NOT_SUPPORTED);

		BDDMockito.when(apiRepo.findByApiLabel("myIntegration")).thenReturn(integrationEntity);

		try {
			apiService.register("myIntegration");
			MatcherAssert.assertThat("Exception not thrown", false);
		} catch (ApiIntegrationException e) {
			MatcherAssert.assertThat(e.getMessage(),
					Matchers.is("API integration cannot be registered in state Not Supported"));
		}

		BDDMockito.verify(apiRepo, Mockito.times(0)).saveAndFlush(integrationEntity);
	}

	@Test
	public void testUnregister() throws Exception {
		IWatchtowerApi api = BDDMockito.mock(IWatchtowerApi.class);
		ApiIntegrationEntity integrationEntity = BDDMockito.mock(ApiIntegrationEntity.class);
		BDDMockito.when(integrationEntity.getApiLabel()).thenReturn("myIntegration");
		BDDMockito.when(integrationEntity.getIntegrationId()).thenReturn(1L);
		BDDMockito.when(integrationEntity.getRegisterState())
				.thenReturn(RegisterState.REGISTERED);
		BDDMockito.when(integrationEntity.createApi()).thenReturn(api);

		BDDMockito.when(apiRepo.findByApiLabel("myIntegration")).thenReturn(integrationEntity);

		apiService.unregister("myIntegration");

		BDDMockito.verify(integrationEntity).setRegisterState(RegisterState.IN_PROGRESS);
		BDDMockito.verify(integrationEntity).setRegisterError(null);
		BDDMockito.verify(api).unregister();
	}

	@Test
	public void testUnregisterFailure() throws Exception {
		IWatchtowerApi api = BDDMockito.mock(IWatchtowerApi.class);
		BDDMockito.doThrow(new IllegalArgumentException("Bad unregistration")).when(api)
				.unregister();
		ApiIntegrationEntity integrationEntity = BDDMockito.mock(ApiIntegrationEntity.class);
		BDDMockito.when(integrationEntity.getApiLabel()).thenReturn("myIntegration");
		BDDMockito.when(integrationEntity.getIntegrationId()).thenReturn(1L);
		BDDMockito.when(integrationEntity.getRegisterState())
				.thenReturn(RegisterState.FAILED);
		BDDMockito.when(integrationEntity.createApi()).thenReturn(api);

		BDDMockito.when(apiRepo.findByApiLabel("myIntegration")).thenReturn(integrationEntity);

		apiService.unregister("myIntegration");

		BDDMockito.verify(integrationEntity).setRegisterState(RegisterState.IN_PROGRESS);
		BDDMockito.verify(integrationEntity).setRegisterError(null);
		BDDMockito.verify(api).unregister();
	}

	@Test
	public void testUnregisterUnknownApiLabel() {
		try {
			apiService.unregister("myIntegration");
			MatcherAssert.assertThat("Exception not thrown", false);
		} catch (ApiIntegrationException e) {
			MatcherAssert.assertThat(e.getMessage(), Matchers.is("Unknown API integration label"));
		}

		BDDMockito.verify(apiRepo, Mockito.times(0)).saveAndFlush(BDDMockito.any());
	}

	@Test
	public void testUnregisterInvalidState() {
		ApiIntegrationEntity integrationEntity = BDDMockito.mock(ApiIntegrationEntity.class);
		BDDMockito.when(integrationEntity.getApiLabel()).thenReturn("myIntegration");
		BDDMockito.when(integrationEntity.getIntegrationId()).thenReturn(1L);
		BDDMockito.when(integrationEntity.getRegisterState())
				.thenReturn(RegisterState.NOT_REGISTERED);

		BDDMockito.when(apiRepo.findByApiLabel("myIntegration")).thenReturn(integrationEntity);

		try {
			apiService.unregister("myIntegration");
			MatcherAssert.assertThat("Exception not thrown", false);
		} catch (ApiIntegrationException e) {
			MatcherAssert.assertThat(e.getMessage(),
					Matchers.is("API integration cannot be unregistered in state Not Registered"));
		}

		BDDMockito.verify(apiRepo, Mockito.times(0)).saveAndFlush(integrationEntity);
	}
}
