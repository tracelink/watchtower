package com.tracelink.appsec.watchtower.core.assistant;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.transaction.PlatformTransactionManager;
import com.tracelink.appsec.watchtower.core.persistence.AssistantBudgetDailyEntity;
import com.tracelink.appsec.watchtower.core.persistence.LedgerRepository;

/** The side panel's model chip, mode chip, history label and budget chip read these endpoints. */
class AssistantChatPanelDataTest {
 private static final long CAP=2_000_000L;
 private final LedgerRepository records=mock(LedgerRepository.class);
 private final AssistantBudgetService budgets=new AssistantBudgetService(records,mock(PlatformTransactionManager.class));
 private final AssistantSettingsService settings=mock(AssistantSettingsService.class);
 private final AssistantPersistence db=mock(AssistantPersistence.class);
 private final AssistantController controller=new AssistantController(db,settings,mock(AssistantAccess.class),mock(AssistantToolRegistry.class),mock(AssistantStreams.class),budgets);
 private final TestingAuthenticationToken engineer=new TestingAuthenticationToken("engineer",null,"Assistant Use");

 private void configure(boolean actions){
  var model=new AssistantSettings.Model("m1",List.of("low"),1024,128,1,1,"2026-10-01","ref");
  var cfg=new AssistantSettings(true,14,List.of(model),"m1","low",1,1,1024,128,512,2048,10000,10000,10000,10000,CAP,10000,5,60,5,null,null,actions);
  when(settings.get()).thenReturn(new AssistantSettingsService.Versioned(1,cfg));
 }

 @Test void budgetIsTheCallersSpendTodayAgainstTheirDailyCap(){
  configure(false);
  long today=LocalDate.now(ZoneOffset.UTC).atStartOfDay(ZoneOffset.UTC).toInstant().toEpochMilli();
  when(records.find(eq(AssistantBudgetDailyEntity.class),eq(new AssistantBudgetDailyEntity.Id(AssistantPersistence.ownerKey("engineer"),today)))).thenReturn(new AssistantBudgetDailyEntity(AssistantPersistence.ownerKey("engineer"),today,10L,120_000L));
  @SuppressWarnings("unchecked") var view=(Map<String,Object>)controller.budget(engineer);
  assertEquals(120_000L,view.get("usedCostMicros"));assertEquals(CAP,view.get("dailyCostMicros"));
  assertEquals(0L,view.get("orgUsedCostMicros"),"the organization's day is listed beside the person's");assertEquals(List.of(),view.get("features"),"no feature has a share yet");
  assertEquals(0L,budgets.usedTodayMicros("nobody"),"no bucket yet means nothing spent");
 }

 @Test @SuppressWarnings("unchecked") void modelsSayHowLongChatsAreKeptAndWhetherRulesetActionsAreOn(){
  configure(false);
  var off=(Map<String,Object>)controller.models(engineer);
  assertEquals(14,off.get("retentionDays"));assertEquals(false,off.get("rulesetActions"));
  configure(true);
  assertEquals(true,((Map<String,Object>)controller.models(engineer)).get("rulesetActions"));
 }
}
