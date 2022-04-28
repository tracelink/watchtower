package com.tracelink.appsec.watchtower.core.rest.scan.image;

import com.tracelink.appsec.watchtower.core.auth.model.CorePrivilege;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.result.PRResultFilter;
import com.tracelink.appsec.watchtower.core.scan.image.result.ImageResultFilter;
import com.tracelink.appsec.watchtower.core.scan.image.result.ImageScanResult;
import com.tracelink.appsec.watchtower.core.scan.image.service.ImageScanResultService;
import com.tracelink.appsec.watchtower.core.scan.image.service.ImageScanningService;
import java.nio.file.Paths;
import java.util.List;
import java.util.Optional;
import net.minidev.json.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.util.UriComponentsBuilder;

@RestController
@RequestMapping("/rest/imagescan/result")
@PreAuthorize("hasAuthority('" + CorePrivilege.SCAN_RESULTS_NAME + "')")
public class ImageScanResultController {

	private final ImageScanResultService resultService;

	public ImageScanResultController(@Autowired ImageScanningService scanService,
			@Autowired ImageScanResultService resultService) {
		this.resultService = resultService;
	}

	@GetMapping(value = {"", "/{filter}", "/{filter}/{page}"},
			produces = MediaType.APPLICATION_JSON_VALUE)
	ResponseEntity<JSONObject> getResults(@PathVariable Optional<String> filter,
			@PathVariable Optional<Integer> page, UriComponentsBuilder uriBuilder) {
		ImageResultFilter resultFilter =
				ImageResultFilter.toFilter(filter.orElse(PRResultFilter.ALL.getName()));
		int pageNum = page.orElse(0);
		List<ImageScanResult> results =
				resultService.getScanResultsWithFilters(resultFilter, 10, pageNum);
		String next = uriBuilder.replacePath(
				Paths.get("rest/scan/result", resultFilter.getName(), String.valueOf(pageNum + 1))
						.toString()).build().encode().toUriString();
		JSONObject obj = new JSONObject();
		if (!results.isEmpty()) {
			obj.put("next", next);
		}
		obj.put("results", results);
		return ResponseEntity.ok(obj);
	}

}
