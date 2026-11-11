package com.tracelink.appsec.watchtower.web;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.*;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;
import com.tracelink.appsec.watchtower.core.rule.*;
import com.tracelink.appsec.watchtower.core.rule.candidate.*;
import com.tracelink.appsec.module.regex.model.RegexCustomRuleDto;

/** Real HTTP converter, module DTO, service, JPA and canonical history boundary. */
@SpringBootTest(properties={"watchtower.runAfterStartup=false", "watchtower.rule-testing.enabled=false"})
@AutoConfigureMockMvc @ActiveProfiles("dev") @Transactional
class RuleCandidateMvcTest {
 @Autowired MockMvc mvc;
 @Autowired RuleRepository rules;
 @Autowired RuleCandidateService candidates;
 @Test void workspaceAndDraftKeepRealDefinitionAndCanonicalRevision() throws Exception {
  var dto=new RegexCustomRuleDto();dto.setName("UAT MVC candidate");dto.setAuthor("reviewer");
  dto.setMessage("Review match");dto.setPriority(RulePriority.HIGH);dto.setExternalUrl("https://example.test/rule");
  dto.setRegexPattern("unsafe|risky");dto.setFileExtension("");
  var active=rules.saveAndFlush(dto.toEntity());long id=active.getId();
  String canonical=RuleDefinitionHistory.definition(active.toDto()),revision=active.toDto().getRevision();
  var reviewer=user("reviewer").authorities(()->"Rule Modify");
  mvc.perform(get("/rule/candidates/workspace/"+id).with(reviewer).accept("application/json"))
    .andExpect(status().isOk()).andExpect(jsonPath("$.definition.regexPattern").value("unsafe|risky"))
    .andExpect(jsonPath("$.definition.fileExtension").value(""))
    .andExpect(jsonPath("$.fieldMetadata.regexPattern.type").value("string"))
    .andExpect(jsonPath("$.authoringAvailable").value(true)).andExpect(jsonPath("$.definition.nodeType").doesNotExist());
  String body="{\"ruleId\":"+id+",\"baseRevision\":\""+revision+"\",\"changes\":{\"regexPattern\":\"risky\",\"fileExtension\":\"\"},\"rationale\":\"Reviewed narrower matcher\"}";
  mvc.perform(post("/rule/candidates").with(reviewer).with(csrf()).contentType("application/json").content(body))
    .andExpect(status().isOk()).andExpect(jsonPath("$.id").isString());
  assertEquals(1,candidates.list(id,0).size());
  assertEquals(canonical,RuleDefinitionHistory.definition(rules.findById(id).orElseThrow().toDto()));
  assertEquals(revision,active.toDto().getRevision());
  for(String changes:new String[]{"{\"priority\":\"LOW\"}","{\"regexPattern\":null}","{}","[]"}) {
   mvc.perform(post("/rule/candidates").with(reviewer).with(csrf()).contentType("application/json")
     .content("{\"ruleId\":"+id+",\"baseRevision\":\""+revision+"\",\"changes\":"+changes+",\"rationale\":\"Invalid draft\"}"))
     .andExpect(status().isBadRequest());
  }
  assertEquals(1,candidates.list(id,0).size());
 }
}
