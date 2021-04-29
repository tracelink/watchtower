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

	private static Gson gson = new Gson();

	private static final Type MAP_TYPE = new TypeToken<Map<String, Map<String, String>>>() {
	}.getType();

	@PostMapping("/rest/csp/report")
	ResponseEntity<String> submitCspReport(@RequestBody String report) {
		try {
			Map<String, Map<String, String>> reportMap = gson.fromJson(report, MAP_TYPE);
			Map<String, String> cspReport = reportMap.get("csp-report");
			String cspViolation = "CSP violation of " + cspReport.get("violated-directive")
					+ " directive at "
					+ cspReport.get("referrer") + ". Blocked URI: " + cspReport.get("blocked-uri");
			LOG.info(cspViolation);
			return ResponseEntity.ok().body("Received report");
		} catch (Exception e) {
			return ResponseEntity.badRequest().body("Invalid report");
		}
	}
}
