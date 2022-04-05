package com.tracelink.appsec.watchtower.core.rest.scan.image;

import java.nio.file.Paths;
import java.util.List;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.util.UriComponentsBuilder;

import com.tracelink.appsec.watchtower.core.auth.model.CorePrivilege;
import com.tracelink.appsec.watchtower.core.scan.image.result.ImageResultFilter;
import com.tracelink.appsec.watchtower.core.scan.image.result.ImageScanResult;
import com.tracelink.appsec.watchtower.core.scan.image.service.ImageScanResultService;

import net.minidev.json.JSONObject;

@RestController
@RequestMapping("/rest/image/result")
@PreAuthorize("hasAuthority('" + CorePrivilege.SCAN_RESULTS_NAME + "')")
public class ImageScanResultsRestController {
	private ImageScanResultService scanResultService;

	public ImageScanResultsRestController(@Autowired ImageScanResultService scanResultService) {
		this.scanResultService = scanResultService;
	}

	@GetMapping(value = {"", "/{filter}", "/{filter}/{page}"})
	public ResponseEntity<JSONObject> getResults(@PathVariable Optional<String> filter,
			@PathVariable Optional<Integer> page, UriComponentsBuilder uriBuilder) {
		ImageResultFilter resultFilter =
				ImageResultFilter.toFilter(filter.orElse(ImageResultFilter.ALL.getName()));
		int pageNum = page.orElse(0);
		List<ImageScanResult> results =
				scanResultService.getScanResultsWithFilters(resultFilter, 10, pageNum);
		String next =
				uriBuilder
						.replacePath(Paths.get("rest/uploadscan/result", resultFilter.getName(),
								String.valueOf(pageNum + 1)).toString())
						.build().encode().toUriString();
		JSONObject obj = new JSONObject();
		if (!results.isEmpty()) {
			obj.put("next", next);
		}
		obj.put("results", results);
		return ResponseEntity.ok(obj);
	}
}
