package com.tracelink.appsec.watchtower.core.rest.scan.image;

import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.tracelink.appsec.watchtower.core.auth.model.CorePrivilege;
import com.tracelink.appsec.watchtower.core.scan.image.service.ImageAdvisoryService;

import kong.unirest.json.JSONArray;
import kong.unirest.json.JSONObject;

@RestController
@RequestMapping("/rest/advisory")
@PreAuthorize("hasAuthority('" + CorePrivilege.SCAN_RESULTS_NAME + "')")
public class AdvisoryRestController {
	private ImageAdvisoryService imageAdvisoryService;

	public AdvisoryRestController(@Autowired ImageAdvisoryService imageAdvisoryService) {
		this.imageAdvisoryService = imageAdvisoryService;
	}

	@GetMapping(value = "", produces = MediaType.APPLICATION_JSON_VALUE)
	public ResponseEntity<Map<String, Object>> getAllAdvisories() {
		JSONObject json = new JSONObject();
		json.put("total", imageAdvisoryService.getTotalNumberAdvisories());
		json.put("advisories", new JSONArray(imageAdvisoryService.getAllAdvisories()));
		return ResponseEntity.ok(json.toMap());
	}

}
