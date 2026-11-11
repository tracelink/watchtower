package com.tracelink.appsec.watchtower.core.assistant;

import java.util.*;
import org.h2.jdbcx.JdbcDataSource;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.init.ResourceDatabasePopulator;
import org.springframework.core.io.ClassPathResource;
import org.springframework.orm.jpa.*;
import org.springframework.orm.jpa.vendor.HibernateJpaVendorAdapter;
import org.springframework.orm.jpa.hibernate.SpringBeanContainer;
import org.springframework.beans.factory.support.DefaultListableBeanFactory;
import org.springframework.aop.framework.ProxyFactory;
import org.springframework.transaction.annotation.AnnotationTransactionAttributeSource;
import org.springframework.transaction.interceptor.TransactionInterceptor;
import com.tracelink.appsec.watchtower.core.persistence.*;
import com.tracelink.appsec.watchtower.core.rule.*;
import com.tracelink.appsec.watchtower.core.rule.candidate.*;
import jakarta.persistence.*;

/** Real Hibernate transactions over the new migration artifacts; preceding schemas come from ORM. */
public class R1Database implements AutoCloseable {
 public final JdbcTemplate jdbc;public final JpaTransactionManager tx;public final LedgerRepository records;
 private final EntityManagerFactory factory;
 public R1Database(){
  var ds=new JdbcDataSource();ds.setURL("jdbc:h2:mem:"+UUID.randomUUID()+";MODE=MySQL;DATABASE_TO_LOWER=TRUE;DB_CLOSE_DELAY=-1");jdbc=new JdbcTemplate(ds);
  var beans=new DefaultListableBeanFactory();
  beans.registerSingleton("dataEncryptionService",org.mockito.Mockito.mock(com.tracelink.appsec.watchtower.core.encryption.service.DataEncryptionService.class));
  beans.registerSingleton("keyEncryptionService",org.mockito.Mockito.mock(com.tracelink.appsec.watchtower.core.encryption.service.KeyEncryptionService.class));
  beans.registerSingleton("ruleDefinitionHistory",org.mockito.Mockito.mock(RuleDefinitionHistory.class));
  // These fixtures seed rules with SQL; web persistence tests exercise the actual Spring listener.
  beans.registerSingleton("ruleDefinitionListener",new RuleDefinitionListener(org.mockito.Mockito.mock(RuleDefinitionHistory.class)));
  var builder=new LocalContainerEntityManagerFactoryBean();builder.setDataSource(ds);builder.setJpaVendorAdapter(new HibernateJpaVendorAdapter());
  builder.setPackagesToScan("com.tracelink.appsec.watchtower.core");
  builder.setPersistenceUnitPostProcessors(unit->unit.getManagedClassNames().add(com.tracelink.ormfixtures.PersistedTestRule.class.getName()));
  builder.setJpaPropertyMap(Map.of("hibernate.hbm2ddl.auto","create","hibernate.resource.beans.container",new SpringBeanContainer(beans)));
  builder.afterPropertiesSet();factory=builder.getObject();tx=new JpaTransactionManager(factory);tx.setDataSource(ds);
  records=service(new LedgerRepository(SharedEntityManagerCreator.createSharedEntityManager(factory)));
  // Drop only the new ledgers, then apply their actual migration files to the preceding schema.
  for(var name:jdbc.queryForList("SELECT table_name FROM information_schema.tables WHERE table_schema='public'",String.class))
   if((name.startsWith("assistant_")&&!name.startsWith("assistant_ruleset_"))||name.startsWith("rule_metric_")||Set.of("finding_feedback","finding_feedback_audit","bypass_finding_identity","rule_review_items","rule_review_audit","rule_regression_cases","rule_health","missed_vulnerability_cases","rule_definition_versions","rule_candidates","rule_evaluation_fixtures","rule_candidate_runs","rule_candidate_actions","rule_shadow_observations","application_persistence_locks","module_settings","rule_review_report_settings","rule_review_reports","rule_review_report_items","variant_searches","variant_search_repositories","upstream_rule_snapshots","upstream_updates","assistant_evaluation_runs","assistant_evaluation_results","ai_integrations","rule_review_theme_names","assistant_knowledge","assistant_knowledge_audit","finding_assessments","finding_assessment_views").contains(name))jdbc.execute("DROP TABLE "+name);
  jdbc.execute("ALTER TABLE rules DROP COLUMN definition_version");
  jdbc.execute("ALTER TABLE rules DROP COLUMN upstream_hold_since");
  jdbc.execute("ALTER TABLE pull_request_bypasses DROP COLUMN reason_code");
  jdbc.execute("ALTER TABLE pull_request_bypass_requests DROP COLUMN reason_code");
  var scripts=new ResourceDatabasePopulator();
  for(String name:new String[]{"V062__Rule_Execution_Projection.sql","V063__Finding_Feedback.sql","V064__Rule_Reviews.sql","V065__Assistant_Settings_Storage.sql","V066__Assistant_Durable_Turns.sql","V067__Missed_Vulnerability_Intake.sql","V068__Rule_Candidates.sql","V069__Application_Persistence_Locks.sql","V070__Module_Controls.sql","V071__Rule_Review_Reports.sql","V072__Variant_Searches.sql","V073__Upstream_Rule_Sync.sql","V074__Assistant_Evaluation.sql","V075__AI_Integrations.sql","V076__Rule_Review_Theme_Names.sql","V077__Approved_Knowledge.sql","V078__Finding_Assessments.sql","V082__Rule_Execution_Evidence.sql","V083__Complete_Rule_Review_Report_Items.sql","V086__Assistant_Lifecycle_Retention.sql","V088__Module_File_Types.sql","V089__Assistant_Feature_Reservations.sql","V094__Assistant_Session_Title.sql"})scripts.addScript(new ClassPathResource("db/migration/"+name));scripts.execute(ds);
  // New workflow behavior tests use ORM-created tables; migration verification remains user-owned.
  jdbc.update("INSERT INTO application_persistence_locks(lock_name) VALUES (?)","ruleset-configuration");
 }
 /** A stand-in AI integration whose OpenAI key is configured while {@code configured} is true. */
 public static com.tracelink.appsec.watchtower.core.assistant.integration.AiIntegrationService keys(java.util.concurrent.atomic.AtomicBoolean configured){var keys=org.mockito.Mockito.mock(com.tracelink.appsec.watchtower.core.assistant.integration.AiIntegrationService.class);org.mockito.Mockito.when(keys.view(com.tracelink.appsec.watchtower.core.assistant.integration.AiProvider.OPENAI)).thenAnswer(i->new com.tracelink.appsec.watchtower.core.assistant.integration.AiIntegrationService.View("OPENAI","OpenAI",configured.get(),null,null,null,null,null,0,true));return keys;}
 @SuppressWarnings("unchecked") public <T> T service(T target){
  var proxy=new ProxyFactory(target);proxy.setProxyTargetClass(true);
  proxy.addAdvice(new TransactionInterceptor(tx,new AnnotationTransactionAttributeSource()));return (T)proxy.getProxy();
 }
 public void seedRule(long id,String revision){
  jdbc.update("INSERT INTO rules(rule_id,rule_revision,rule_state,definition_version) VALUES (?,?,'ACTIVE',0)",id,revision);
  jdbc.update("INSERT INTO persisted_test_rules(rule_id) VALUES (?)",id);
 }
 public void seedPr(long id,long end){
  jdbc.update("INSERT INTO pull_request_container(container_id,last_review_date,resolved) VALUES (?,0,FALSE)",id);
  jdbc.update("INSERT INTO pull_request_scans(scan_entity_id,container_id,submit_date,start_date,end_date,blocked,source_size_bytes,total_duration_ms,queue_wait_duration_ms,source_preparation_duration_ms,scanner_execution_duration_ms,result_processing_duration_ms,scm_reporting_duration_ms,persistence_duration_ms,cleanup_duration_ms,performance_complete,changed_file_count) VALUES (?,?,0,0,?,FALSE,0,0,0,0,0,0,0,0,0,FALSE,0)",id,id,end);
 }
 public <T> T repository(Class<T> type){return new org.springframework.data.jpa.repository.support.JpaRepositoryFactory(SharedEntityManagerCreator.createSharedEntityManager(factory)).getRepository(type);}
 @Override public void close(){factory.close();jdbc.execute("DROP ALL OBJECTS");}
}
