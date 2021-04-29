package com.tracelink.appsec.watchtower.core.logging;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.InputStreamResource;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import com.tracelink.appsec.watchtower.core.auth.model.CorePrivilege;
import com.tracelink.appsec.watchtower.core.mvc.WatchtowerModelAndView;

import ch.qos.logback.classic.Level;

/**
 * Controller for all Logging. Handles setting the log level and outputting recent log messages for
 * watchtower
 *
 * @author csmith
 */
@Controller
@PreAuthorize("hasAuthority('" + CorePrivilege.LOGGING_VIEW_NAME + "')")
public class LoggingController {
	private static final Logger LOG = LoggerFactory.getLogger(LoggingController.class);

	private LogsService logsService;

	public LoggingController(@Autowired LogsService logsService) {
		this.logsService = logsService;
	}

	private List<Level> allowedLevels =
			Arrays.asList(Level.TRACE, Level.DEBUG, Level.INFO, Level.WARN, Level.ERROR);

	@GetMapping("/logging")
	public WatchtowerModelAndView logging() {
		WatchtowerModelAndView mav = new WatchtowerModelAndView("admin/logging");
		mav.addObject("currentLogLevel", logsService.getLogsLevel().levelStr);
		mav.addObject("logOptions", allowedLevels);
		mav.addObject("logs", logsService.getLogs());
		return mav;
	}

	@PostMapping("/logging/set")
	@PreAuthorize("hasAuthority('" + CorePrivilege.LOGGING_MODIFY_NAME + "')")
	public String setLogLevel(@RequestParam String loglevel) {
		Level level = Level.toLevel(loglevel, Level.INFO);
		if (!allowedLevels.contains(level)) {
			level = Level.INFO;
		}
		logsService.setLogsLevel(level);
		return "redirect:/logging";
	}

	@GetMapping("/logging/download")
	@PreAuthorize("hasAuthority('" + CorePrivilege.LOGGING_DOWNLOAD_NAME + "')")
	public ResponseEntity<Object> downloadLogsFiles() {
		File file;
		Resource resource;
		try {
			file = logsService.generateLogsZip().toFile();
			resource = new InputStreamResource(new FileInputStream(file));
		} catch (IOException e) {
			LOG.error("Exception while zipping logs", e);
			return ResponseEntity.status(HttpStatus.NOT_FOUND).body("Exception while zipping logs");
		}

		return ResponseEntity.ok()
				.header(HttpHeaders.CONTENT_DISPOSITION, "attachment;filename=watchtowerlogs.zip")
				.header(HttpHeaders.CONTENT_TYPE, "application/gzip").contentLength(file.length())
				.body(resource);
	}

}
