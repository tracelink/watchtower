package com.tracelink.appsec.watchtower.web;

import static org.junit.jupiter.api.Assertions.*;

import java.util.List;
import jakarta.persistence.EntityManager;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.transaction.annotation.Transactional;
import com.tracelink.appsec.module.pmd.model.*;
import com.tracelink.appsec.watchtower.core.rule.*;
import com.tracelink.appsec.watchtower.core.rule.candidate.RuleDefinitionHistory;

/** Actual JPA callbacks, optimistic versions and replacement child collections, using H2 migrations. */
@SpringBootTest(properties = {"watchtower.rule-testing.enabled=false", "watchtower.runAfterStartup=false"})
@ActiveProfiles("dev")
@Transactional
class RuleCandidatePersistenceTest {
 @Autowired EntityManager entities;
 @Autowired RuleRepository rules;
 @Autowired RuleDefinitionHistory history;
 @Autowired JdbcTemplate jdbc;
 @Autowired org.springframework.transaction.PlatformTransactionManager transactions;

 @Test void opengrepRulesPersistStableIdsLicensedDefinitionAndHistoryWhileDisabled()throws Exception {
  var dto=new com.tracelink.appsec.module.opengrep.model.OpengrepCustomRuleDto();dto.setName("R4 persisted rule");dto.setAuthor("reviewer");dto.setMessage("Review eval");dto.setPriority(RulePriority.HIGH);dto.setExternalUrl("https://example.test/rule");dto.setEngineRuleId("reviewed.eval");dto.setLicense("MIT");dto.setSource("reviewed/fixture-v1");dto.setDefinition("{\"languages\":[\"python\"],\"pattern\":\"eval(...)\"}");
  var saved=rules.saveAndFlush(dto.toEntity());long id=saved.getId();entities.clear();var reloaded=rules.findById(id).orElseThrow();
  assertEquals(dto.getRevision(),reloaded.toDto().getRevision());assertEquals("reviewed.eval",reloaded.toDto().getExternalRuleKey());assertEquals(1,history.list(id,0).size());
  String exported=RuleDefinitionHistory.definition(reloaded.toDto());var imported=RuleDefinitionHistory.JSON.readValue(exported,com.tracelink.appsec.module.opengrep.model.OpengrepCustomRuleDto.class);assertEquals(dto.getDefinition(),imported.getDefinition());assertEquals("MIT",imported.getLicense());
  assertEquals(0,jdbc.queryForObject("SELECT enabled FROM module_settings WHERE module_name='opengrep'",Integer.class));assertEquals(1,jdbc.queryForObject("SELECT COUNT(*) FROM opengrep_rules WHERE rule_id=?",Integer.class,id));
 }
 @Test void definitionWritesAndReplacementKeepHistoryVersionsAndChildRowsConsistent() {
  var dto = new PMDCustomRuleDto();
  dto.setName("R3 persistence contract");dto.setAuthor("reviewer");dto.setPriority(RulePriority.HIGH);
  dto.setMessage("Reviewed finding");dto.setExternalUrl("https://example.test/rule");
  dto.setParserLanguage("java");dto.setRuleClass("net.sourceforge.pmd.lang.rule.xpath.XPathRule");
  dto.setProperties(List.of(property("//MethodDeclaration")));
  var initial = dto.toEntity();initial.setAuthor("reviewer");
  var active = (PMDRuleEntity) rules.saveAndFlush(initial);
  long id = active.getId();
  String original = active.toDto().getRevision();
  assertEquals(1, history.list(id, 0).size());
  active.setMessage("Updated finding");active.refreshRevision();rules.saveAndFlush(active);
  assertEquals(1, active.getPersistenceVersion());assertEquals(2, history.list(id, 0).size());
  assertNotEquals(original, active.toDto().getRevision());

  var replacementDto = (PMDCustomRuleDto) active.toDto();
  replacementDto.setProperties(List.of(property("//VariableId")));
  var replacement = replacementDto.toEntity();
  replacement.setId(id);replacement.setAuthor(active.getAuthor());replacement.preserveStewardshipFrom(active);replacement.refreshRevision();
  rules.saveAndFlush(replacement);entities.clear();
  var reloaded = (PMDRuleEntity) rules.findById(id).orElseThrow();
  assertEquals(2, reloaded.getPersistenceVersion());
  assertEquals("//VariableId", reloaded.getProperties().iterator().next().getValue());
  assertEquals(1, jdbc.queryForObject("SELECT COUNT(*) FROM pmd_properties WHERE rule_id=?", Integer.class, id));
  assertEquals(3, history.list(id, 0).size());
  assertEquals(RulePriority.HIGH, reloaded.getPriority());
 }

 @Test @Transactional(propagation=org.springframework.transaction.annotation.Propagation.NOT_SUPPORTED)
 void committedAndRolledBackDirtyWritesKeepDefinitionHistoryAtomic() {
  var transaction=new org.springframework.transaction.support.TransactionTemplate(transactions);
  var dto=new PMDCustomRuleDto();dto.setName("ORM commit history contract");dto.setAuthor("reviewer");dto.setPriority(RulePriority.HIGH);dto.setMessage("Original");dto.setExternalUrl("https://example.test/rule");dto.setParserLanguage("java");dto.setRuleClass("net.sourceforge.pmd.lang.rule.xpath.XPathRule");dto.setProperties(List.of(property("//MethodDeclaration")));
  Long id=transaction.execute(tx->{var entity=dto.toEntity();entity.setAuthor("reviewer");return rules.save(entity).getId();});
  assertEquals(1,history.list(id,0).size());
  transaction.executeWithoutResult(tx->{var entity=rules.findById(id).orElseThrow();entity.setMessage("Committed dirty write");});
  assertEquals(2,history.list(id,0).size());assertEquals("Committed dirty write",rules.findById(id).orElseThrow().getMessage());
  assertThrows(IllegalStateException.class,()->transaction.executeWithoutResult(tx->{var entity=rules.findById(id).orElseThrow();entity.setMessage("Rolled back dirty write");entities.flush();history.list(id,0);throw new IllegalStateException("rollback");}));
  assertEquals(2,history.list(id,0).size());assertEquals("Committed dirty write",rules.findById(id).orElseThrow().getMessage());
  // Existing snapshots from the earlier implementation retain their arbitrary IDs.
  for(String version:jdbc.queryForList("SELECT version_id FROM rule_definition_versions WHERE rule_id=?",String.class,id))jdbc.update("UPDATE rule_definition_versions SET version_id=? WHERE version_id=?",java.util.UUID.randomUUID().toString(),version);
  history.record(rules.findById(id).orElseThrow().toDto());assertEquals(2,history.list(id,0).size());
  transaction.executeWithoutResult(tx->rules.deleteById(id));
 }

 private PMDPropertyDto property(String xpath) {
  var property = new PMDPropertyDto();property.setName("xpath");property.setValue(xpath);return property;
 }
}
