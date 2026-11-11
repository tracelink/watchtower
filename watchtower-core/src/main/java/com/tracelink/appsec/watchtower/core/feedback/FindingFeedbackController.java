package com.tracelink.appsec.watchtower.core.feedback;

import java.util.*;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/finding-feedback")
@PreAuthorize("hasAuthority('Scan Results View') and hasAuthority('Finding Feedback')")
public class FindingFeedbackController {
 private final FindingFeedbackService feedback;
 public FindingFeedbackController(FindingFeedbackService feedback){this.feedback=feedback;}
 @PostMapping public Map<String,String> save(@RequestBody FindingFeedbackService.Update update,Authentication a){feedback.save(update,a.getName());return Map.of("status","saved");}
 @GetMapping public List<Map<String,Object>> scan(@RequestParam String scanType,@RequestParam long scanId){return feedback.forScan(scanType,scanId);}
 @GetMapping("/audit") public List<Map<String,Object>> audit(@RequestParam String scanType,@RequestParam long scanId,@RequestParam String findingKey){return feedback.audit(scanType,scanId,findingKey);}
}
