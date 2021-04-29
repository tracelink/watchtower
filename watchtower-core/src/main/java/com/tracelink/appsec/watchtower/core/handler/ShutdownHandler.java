package com.tracelink.appsec.watchtower.core.handler;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.context.ApplicationContext;
import org.springframework.stereotype.Service;

import com.tracelink.appsec.watchtower.core.scan.scm.pr.service.PRScanningService;
import com.tracelink.appsec.watchtower.core.scan.upload.service.UploadScanningService;

/**
 * Handles a graceful shutdown
 *
 * @author csmith
 */
@Service
public class ShutdownHandler {
	private static Logger LOG = LoggerFactory.getLogger(ShutdownHandler.class);

	private final ExecutorService executor;

	private PRScanningService prScanService;

	private UploadScanningService uploadScanService;

	private ApplicationContext ctx;

	public ShutdownHandler(@Autowired PRScanningService prScanService,
			@Autowired UploadScanningService uploadScanService,
			@Autowired ApplicationContext ctx) {
		this.executor = Executors.newSingleThreadExecutor();
		this.prScanService = prScanService;
		this.uploadScanService = uploadScanService;
		this.ctx = ctx;
	}

	/**
	 * Gracefully end executor and threads and quit this application
	 */
	public void executeShutdown() {
		LOG.info("Initiating a shutdown now");
		this.executor.execute(() -> {
			prScanService.shutdown();
			uploadScanService.shutdown();
			SpringApplication.exit(ctx);
			LOG.info("Shutdown complete");
		});
		this.executor.shutdown();
		try {
			this.executor.awaitTermination(10, TimeUnit.SECONDS);
		} catch (InterruptedException e) {
			e.printStackTrace();
		}
	}

}
