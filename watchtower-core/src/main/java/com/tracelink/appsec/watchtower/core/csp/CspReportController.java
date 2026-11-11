package com.tracelink.appsec.watchtower.core.csp;

import java.lang.reflect.Type;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;

/**
 * Rest Controller to take in CSP reports from client machines and log them
 * 
 * @author csmith
 *
 */
@RestController
public class CspReportController {
	private static final Logger LOG = LoggerFactory.getLogger(CspReportController.class);
	private static final int MAX_REPORT_LENGTH = 16_384;

	private static final Gson GSON = new Gson();

	private static final Type MAP_TYPE = new TypeToken<Map<String, Map<String, String>>>() {
	}.getType();

	@PostMapping("/rest/csp/report")
	ResponseEntity<String> submitCspReport(@RequestBody String report) {
		try {
			if (report.length() > MAX_REPORT_LENGTH) {
				return ResponseEntity.badRequest().body("Invalid report");
			}
			Map<String, Map<String, String>> reportMap = GSON.fromJson(report, MAP_TYPE);
			Map<String, String> cspReport = reportMap.get("csp-report");
			LOG.info("CSP violation of {} directive at {}. Blocked URI: {}",
					sanitize(cspReport.get("violated-directive")),
					sanitize(cspReport.get("referrer")), sanitize(cspReport.get("blocked-uri")));
			return ResponseEntity.ok().body("Received report");
		} catch (Exception e) {
			return ResponseEntity.badRequest().body("Invalid report");
		}
	}

	private String sanitize(String value) {
		if (value == null) return "unknown";
		return value.replace('\r', ' ').replace('\n', ' ').replace('\t', ' ');
	}
}
