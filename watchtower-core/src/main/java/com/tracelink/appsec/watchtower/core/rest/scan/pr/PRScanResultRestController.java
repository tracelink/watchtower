package com.tracelink.appsec.watchtower.core.rest.scan.pr;

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
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.result.PRResultFilter;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.result.PRScanResult;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.service.PRScanResultService;

import net.minidev.json.JSONObject;

/**
 * Rest resource to display information about PR scan results based on filter criteria
 * 
 * @author csmith
 *
 */
@RestController
@RequestMapping("/rest/scan/result")
@PreAuthorize("hasAuthority('" + CorePrivilege.SCAN_RESULTS_NAME + "')")
public class PRScanResultRestController {

	private PRScanResultService resultService;

	public PRScanResultRestController(@Autowired PRScanResultService resultService) {
		this.resultService = resultService;
	}

	@GetMapping(value = {"", "/{filter}", "/{filter}/{page}"})
	ResponseEntity<JSONObject> getResults(@PathVariable Optional<String> filter,
			@PathVariable Optional<Integer> page, UriComponentsBuilder uriBuilder) {
		PRResultFilter resultFilter =
				PRResultFilter.toFilter(filter.orElse(PRResultFilter.ALL.getName()));
		int pageNum = page.orElse(0);
		List<PRScanResult> results =
				resultService.getScanResultsWithFilters(resultFilter, 10, pageNum);
		String next =
				uriBuilder
						.replacePath(Paths.get("rest/scan/result", resultFilter.getName(),
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
