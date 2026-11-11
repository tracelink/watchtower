package com.tracelink.appsec.watchtower.core.handler;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.BDDMockito;
import org.mockito.MockitoAnnotations;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.context.ApplicationContext;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.service.PRScanningService;
import com.tracelink.appsec.watchtower.core.scan.code.upload.service.UploadScanningService;

@ExtendWith(SpringExtension.class)
public class ShutdownHandlerTest {
	@MockitoBean
	private ApplicationContext ctx;

	@MockitoBean
	private PRScanningService prScan;

	@MockitoBean
	private UploadScanningService upScan;

	private ShutdownHandler handler;

	@BeforeEach
	public void setup() {
		this.handler = new ShutdownHandler(prScan, upScan, ctx);
	}

	@Test
	public void applicationShutdownTest() throws Exception {
		// get the injected mock ctx and scan into the handler
		try (AutoCloseable closeable = MockitoAnnotations.openMocks(this)) {
			handler.executeShutdown();
			BDDMockito.verify(prScan, BDDMockito.times(1)).shutdown();
			BDDMockito.verify(upScan, BDDMockito.times(1)).shutdown();
		}
	}

}
