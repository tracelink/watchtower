package com.tracelink.appsec.watchtower.core.rest.scan.image;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.tracelink.appsec.watchtower.core.auth.model.CorePrivilege;
import com.tracelink.appsec.watchtower.core.scan.image.entity.AdvisoryEntity;
import com.tracelink.appsec.watchtower.core.scan.image.service.ImageAdvisoryService;

import kong.unirest.json.JSONArray;
import kong.unirest.json.JSONObject;

@RestController
@RequestMapping("/rest/advisory")
@PreAuthorize("hasAuthority('" + CorePrivilege.SCAN_RESULTS_NAME + "')")
public class AdvisoryRest {
	private ImageAdvisoryService imageAdvisoryService;

	public AdvisoryRest(@Autowired ImageAdvisoryService imageAdvisoryService) {
		this.imageAdvisoryService = imageAdvisoryService;
	}

	@GetMapping(value = "", produces = MediaType.APPLICATION_JSON_VALUE)
	public ResponseEntity<Map<String, Object>> getAdvisoryPage(@RequestParam Optional<Integer> page,
			@RequestParam Optional<Integer> size) {
		JSONObject json = new JSONObject();
		long count = imageAdvisoryService.getTotalNumberAdvisories();
		json.put("total", count);

		boolean all = !page.isPresent() || !size.isPresent();
		if (all) {
			json.put("advisories",
					new JSONArray(imageAdvisoryService.getAllAdvisories()));
		} else {
			json.put("advisories",
					new JSONArray(imageAdvisoryService.getAllAdvisories(page.get(), size.get())));
			if (count > size.get() * (page.get() + 1)) {
				json.put("nextpage",
						"/rest/advisory?page=" + (page.get() + 1) + "&size=" + size.get());
			}
		}

		return ResponseEntity.ok(json.toMap());
	}

	@GetMapping(value = "/search", produces = MediaType.APPLICATION_JSON_VALUE)
	public ResponseEntity<List<AdvisoryEntity>> searchAdvisory(@RequestParam String query) {
		return ResponseEntity.ok(imageAdvisoryService.findByNameContains(query));
	}
}
