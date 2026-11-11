package com.tracelink.appsec.watchtower.web;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;
import com.tracelink.appsec.module.awssecurity.*;
import com.tracelink.appsec.watchtower.core.rule.*;
import com.tracelink.appsec.watchtower.core.scan.repository.*;

/** Packaged module discovery, real joined-rule migration and protected MVC rendering. No AWS calls. */
@SpringBootTest(properties={"watchtower.runAfterStartup=false", "watchtower.rule-testing.enabled=false"})
@AutoConfigureMockMvc @ActiveProfiles("dev") @Transactional
class AwsSecurityApplicationTest {
    @Autowired AwsSecuritySettings settings;
    @Autowired RuleRepository rules;
    @Autowired RepositoryRepository repositories;
    @Autowired MockMvc mvc;
    @Test void packagedModuleRequiresValidResourcesAndItsPolicyRoundTripsThroughJpa() {
        assertNotNull(settings.configurationIssue());
        var policy=new AwsSecurityRuleDto();policy.setName("AWS persisted policy");policy.setPriority(RulePriority.HIGH);
        var saved=rules.saveAndFlush(policy.toEntity());
        assertInstanceOf(AwsSecurityRuleDto.class,rules.findById(saved.getId()).orElseThrow().toDto());
        assertEquals(policy.getRevision(),saved.toDto().getRevision());
    }
    @Test @WithMockUser(authorities={"Scan Results View"})
    void ordinaryViewersCannotReadAdministrationOrOperateRuns() throws Exception {
        mvc.perform(get("/aws-security/readiness")).andExpect(status().isForbidden());
        mvc.perform(get("/aws-security/setup/canary-kit")).andExpect(status().isForbidden());
        mvc.perform(post("/aws-security/runs/unknown/stop").with(csrf())).andExpect(status().isForbidden());
        mvc.perform(get("/scan/report/999/aws/findings/"+"a".repeat(64))).andExpect(status().isNotFound());
    }
    @Test @WithMockUser(authorities={"AWS Security Administration","Repository Settings View","Repository Settings Modify"})
    void oldRepositoryAwsSettingsAreRetired() throws Exception {
        mvc.perform(get("/aws-security/repositories/466/editor")).andExpect(status().isNotFound());
        mvc.perform(post("/aws-security/repositories/466").param("permission","ENABLED").param("version","0").with(csrf())).andExpect(status().isNotFound());
    }
    @Test @WithMockUser(authorities={"AWS Security Administration","Repository Settings View"})
    void syntheticSetupDownloadAndNavigationAreDiscoverableAndDoNotActivate() throws Exception {
        var kit=mvc.perform(get("/aws-security/setup/canary-kit")).andExpect(status().isOk())
            .andExpect(header().string("Content-Disposition","attachment; filename=watchtower-synthetic-canary.zip")).andReturn();
        var names=new java.util.ArrayList<String>();
        try(var zip=new java.util.zip.ZipInputStream(new java.io.ByteArrayInputStream(kit.getResponse().getContentAsByteArray()))){java.util.zip.ZipEntry entry;while((entry=zip.getNextEntry())!=null){names.add(entry.getName());if(entry.getName().equals("receipt.json"))assertTrue(new String(zip.readAllBytes(),java.nio.charset.StandardCharsets.UTF_8).contains("\"uploaded\": false"));}}
        assertEquals(java.util.List.of("source.zip","changes.diff","receipt.json","README.md"),names);
        mvc.perform(get("/repository/pull_request")).andExpect(status().isOk()).andExpect(content().string(org.hamcrest.Matchers.containsString("href=\"/aws-security/readiness/view\"")));
    }
}
