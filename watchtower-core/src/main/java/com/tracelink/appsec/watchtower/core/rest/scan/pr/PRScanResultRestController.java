package com.tracelink.appsec.watchtower.core.rest.scan.pr;

import java.nio.file.Paths;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.util.UriComponentsBuilder;

import com.tracelink.appsec.watchtower.core.auth.model.CorePrivilege;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.mergegate.MergeGateService;
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

	private static final Logger LOG = LoggerFactory.getLogger(PRScanResultRestController.class);

	private PRScanResultService resultService;

	private final MergeGateService mergeGateService;

	public PRScanResultRestController(@Autowired PRScanResultService resultService,
			@Autowired MergeGateService mergeGateService) {
		this.resultService = resultService;
		this.mergeGateService = mergeGateService;
	}

	/**
	 * The merge gate view as JSON: merges in the last {@code days} days by what Watchtower knew
	 * when each happened. Mapped before {@code /{filter}}, which a literal path outranks.
	 *
	 * @param days the window, 1 to 90; 30 if absent
	 * @return the report, or 400 with an error for a window out of range
	 */
	@GetMapping(value = "/merge-gate", produces = MediaType.APPLICATION_JSON_VALUE)
	ResponseEntity<?> getMergeGate(
			@RequestParam(defaultValue = "" + MergeGateService.DEFAULT_DAYS) int days) {
		try {
			return ResponseEntity.ok(mergeGateService.report(days));
		} catch (IllegalArgumentException e) {
			return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
		}
	}

	@GetMapping(value = {"", "/{filter}", "/{filter}/{page}"},
			produces = MediaType.APPLICATION_JSON_VALUE)
	ResponseEntity<JSONObject> getResults(@PathVariable Optional<String> filter,
			@PathVariable Optional<Integer> page, UriComponentsBuilder uriBuilder) {
		PRResultFilter resultFilter =
				PRResultFilter.toFilter(filter.orElse(PRResultFilter.ALL.getName()));
		int pageNum = page.orElse(0);
		long start = System.currentTimeMillis();
		List<PRScanResult> results =
				resultService.getScanResultsWithFilters(resultFilter, 10, pageNum).content();
		LOG.info("getResults: filter={} page={} getScanResultsWithFilters took {} ms for {} row(s)",
				resultFilter.getName(), pageNum, System.currentTimeMillis() - start, results.size());
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
