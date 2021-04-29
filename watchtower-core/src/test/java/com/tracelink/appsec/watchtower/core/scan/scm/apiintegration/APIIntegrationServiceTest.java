package com.tracelink.appsec.watchtower.core.scan.scm.apiintegration;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.BDDMockito;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.context.junit.jupiter.SpringExtension;

@ExtendWith(SpringExtension.class)
public class APIIntegrationServiceTest {

	private APIIntegrationService apiService;

	@MockBean
	private APIIntegrationRepository apiRepo;

	@BeforeEach
	public void setup() {
		this.apiService = new APIIntegrationService(apiRepo);
	}

	@Test
	public void testUpdate() throws ApiIntegrationException {
		APIIntegrationEntity apiEntity = BDDMockito.mock(APIIntegrationEntity.class);
		BDDMockito.when(apiEntity.getApiLabel()).thenReturn("test");
		apiService.save(apiEntity);
		BDDMockito.verify(apiRepo).saveAndFlush(BDDMockito.any());
	}

	@Test
	public void testUpdateBadLabel() {
		Assertions.assertThrows(ApiIntegrationException.class, () -> {
			APIIntegrationEntity apiEntity = BDDMockito.mock(APIIntegrationEntity.class);
			BDDMockito.when(apiEntity.getApiLabel()).thenReturn("test with spaces");
			apiService.save(apiEntity);
			BDDMockito.verify(apiRepo).saveAndFlush(BDDMockito.any());
		});
	}

	@Test
	public void testDeleteExists() {
		APIIntegrationEntity entity = BDDMockito.mock(APIIntegrationEntity.class);
		BDDMockito.when(entity.getApiLabel()).thenReturn("foo");
		BDDMockito.when(apiRepo.getByApiLabel(BDDMockito.anyString())).thenReturn(entity);
		apiService.delete(entity);
		BDDMockito.verify(apiRepo).delete(entity);
		BDDMockito.verify(apiRepo).flush();
	}

	@Test
	public void testDeleteNotExists() {
		APIIntegrationEntity entity = BDDMockito.mock(APIIntegrationEntity.class);
		BDDMockito.when(entity.getApiLabel()).thenReturn("foo");
		BDDMockito.when(apiRepo.getByApiLabel(BDDMockito.anyString())).thenReturn(null);

		apiService.delete(entity);

		BDDMockito.verify(apiRepo, BDDMockito.times(0)).delete(BDDMockito.any());
		BDDMockito.verify(apiRepo, BDDMockito.times(0)).flush();
	}

	@Test
	public void testGetAll() {
		apiService.getAllSettings();
		BDDMockito.verify(apiRepo).findAll();
	}
}
