package com.tracelink.appsec.watchtower.core.assistant;

import java.time.*;
import java.util.*;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import com.tracelink.appsec.watchtower.core.rule.RuleRevision;
import com.tracelink.appsec.watchtower.core.persistence.*;

/** Reserve worst-case cost before every transport attempt; uncertain requests remain charged. */
@Service
public class AssistantBudgetService {
 private final LedgerRepository records;
 private final TransactionTemplate tx;
 private static final String ORG=RuleRevision.definition("assistant-budget","v1").field("scope","organization").hash();
 /** {@code feature} is the slice key this reservation also charged, or null when only the shared buckets were charged. */
 public record Reservation(String id,String user,long bucket,long tokens,long cost,String feature) {
  public Reservation(String id,String user,long bucket,long tokens,long cost){this(id,user,bucket,tokens,cost,null);}
 }
 private static String featureScope(String featureKey){return RuleRevision.definition("assistant-budget-feature","v1").field("feature",featureKey).hash();}
 /** The slice to charge, or null when the feature is unset or has no daily slice (it then shares only the organization and user budgets). */
 private static AssistantSettings.Features.Slice slice(AssistantSettings cfg,AssistantFeature feature){
  if(feature==null)return null;
  var slice=cfg.featureSlice(feature).orElse(null);
  // Bulk work with no slice must not quietly run on the whole organization budget.
  if(slice==null&&feature.needsSlice())throw new IllegalStateException("FEATURE_BUDGET");
  return slice;
 }
 public AssistantBudgetService(LedgerRepository records,PlatformTransactionManager tm){this.records=records;this.tx=new TransactionTemplate(tm);}
 public Reservation reserve(AssistantPersistence.Turn turn,AssistantSettings cfg,AssistantSettings.Model model,long inputUpperBound,long outputUpperBound){
  return reserve(turn,cfg,model,inputUpperBound,outputUpperBound,null);
 }
 /** A turn reservation that also draws on one feature's daily slice (when it has one). */
 public Reservation reserve(AssistantPersistence.Turn turn,AssistantSettings cfg,AssistantSettings.Model model,long inputUpperBound,long outputUpperBound,AssistantFeature feature){
  long tokens=Math.addExact(inputUpperBound,outputUpperBound),cost=model.cost(inputUpperBound,outputUpperBound);
  long bucket=LocalDate.now(ZoneOffset.UTC).atStartOfDay(ZoneOffset.UTC).toInstant().toEpochMilli();String user=AssistantPersistence.ownerKey(turn.owner());
  return tx.execute(s->{
   // An existing singleton serializes creation of today's buckets, including the first request.
   // Reservations and settlement use the same lock order: settings, organization, feature slice, user, turn.
   records.lock(AssistantSettingsEntity.class,1);
   var organization=bucket(ORG,bucket);var slice=slice(cfg,feature);var sliceBucket=slice==null?null:bucket(featureScope(feature.key()),bucket);var individual=bucket(user,bucket);
   charge(organization,cfg.orgDailyTokens(),cfg.orgDailyCostMicros(),tokens,cost);
   if(slice!=null)chargeSlice(sliceBucket,slice,tokens,cost);
   charge(individual,cfg.userDailyTokens(),cfg.userDailyCostMicros(),tokens,cost);
   var current=records.lock(AssistantTurnEntity.class,turn.id());
   if(current==null||!Objects.equals(turn.leaseOwner(),current.leaseOwner)||turn.leaseVersion()!=current.leaseVersion||!Set.of("RUNNING","RECOVERING").contains(current.status))throw new IllegalStateException("LEASE_LOST");
   long requests=records.scalar(Long.class,"SELECT COUNT(r) FROM AssistantRequestReservationEntity r WHERE r.turnId=?1",turn.id());
   if(requests>=cfg.maxRequests()||Math.addExact(current.tokens,tokens)>cfg.turnTokenCap()||Math.addExact(current.costMicros,cost)>cfg.turnCostMicros())throw new IllegalStateException("TURN_BUDGET");
   String id=UUID.randomUUID().toString();
   String sliceKey=slice==null?null:feature.key();
   records.insert(new AssistantRequestReservationEntity(id,turn.id(),user,bucket,tokens,cost,null,null,System.currentTimeMillis(),sliceKey));
   current.tokens+=tokens;current.costMicros+=cost;return new Reservation(id,user,bucket,tokens,cost,sliceKey);
  });
 }
 private AssistantBudgetDailyEntity bucket(String scope,long bucket) {
  var id=new AssistantBudgetDailyEntity.Id(scope,bucket);
  var entity=records.lock(AssistantBudgetDailyEntity.class,id);
  return entity!=null?entity:records.insert(new AssistantBudgetDailyEntity(scope,bucket,0L,0L));
 }
 private void charge(AssistantBudgetDailyEntity bucket,long tokenCap,long costCap,long tokens,long cost){
  long nextTokens=Math.addExact(bucket.chargedTokens,tokens),nextCost=Math.addExact(bucket.chargedCostMicros,cost);
  if(nextTokens>tokenCap||nextCost>costCap)throw new IllegalStateException("SHARED_BUDGET");
  bucket.chargedTokens=nextTokens;bucket.chargedCostMicros=nextCost;
 }
 private void chargeSlice(AssistantBudgetDailyEntity bucket,AssistantSettings.Features.Slice slice,long tokens,long cost){
  long nextTokens=Math.addExact(bucket.chargedTokens,tokens),nextCost=Math.addExact(bucket.chargedCostMicros,cost);
  if(nextTokens>slice.dailyTokens()||nextCost>slice.dailyCostMicros())throw new IllegalStateException("FEATURE_BUDGET");
  bucket.chargedTokens=nextTokens;bucket.chargedCostMicros=nextCost;
 }
 /** A charge outside a chat turn (R6 finding assessment), against the same user and organization daily buckets. */
 public record Charge(String user,long bucket,long tokens,long cost,String feature) {
  public Charge(String user,long bucket,long tokens,long cost){this(user,bucket,tokens,cost,null);}
 }
 public Charge reserveDirect(String owner,AssistantSettings cfg,AssistantSettings.Model model,long inputUpperBound,long outputUpperBound){
  return reserveDirect(owner,cfg,model,inputUpperBound,outputUpperBound,null);
 }
 /** A direct charge that also draws on one feature's daily slice (when it has one). */
 public Charge reserveDirect(String owner,AssistantSettings cfg,AssistantSettings.Model model,long inputUpperBound,long outputUpperBound,AssistantFeature feature){
  long tokens=Math.addExact(inputUpperBound,outputUpperBound),cost=model.cost(inputUpperBound,outputUpperBound);
  long bucket=LocalDate.now(ZoneOffset.UTC).atStartOfDay(ZoneOffset.UTC).toInstant().toEpochMilli();String user=AssistantPersistence.ownerKey(owner);
  return tx.execute(s->{
   records.lock(AssistantSettingsEntity.class,1);
   var slice=slice(cfg,feature);
   charge(bucket(ORG,bucket),cfg.orgDailyTokens(),cfg.orgDailyCostMicros(),tokens,cost);
   if(slice!=null)chargeSlice(bucket(featureScope(feature.key()),bucket),slice,tokens,cost);
   charge(bucket(user,bucket),cfg.userDailyTokens(),cfg.userDailyCostMicros(),tokens,cost);
   return new Charge(user,bucket,tokens,cost,slice==null?null:feature.key());
  });
 }
 /** A cheap pre-check without locks: whether one worst-case request still fits today's user and organization budgets. */
 public boolean canAfford(String owner,AssistantSettings cfg,AssistantSettings.Model model,long inputUpperBound,long outputUpperBound){
  return canAfford(owner,cfg,model,inputUpperBound,outputUpperBound,null);
 }
 /** The same pre-check, also against one feature's daily slice (when it has one). */
 public boolean canAfford(String owner,AssistantSettings cfg,AssistantSettings.Model model,long inputUpperBound,long outputUpperBound,AssistantFeature feature){
  long tokens=inputUpperBound+outputUpperBound,cost=model.cost(inputUpperBound,outputUpperBound);
  long bucket=LocalDate.now(ZoneOffset.UTC).atStartOfDay(ZoneOffset.UTC).toInstant().toEpochMilli();
  var org=records.find(AssistantBudgetDailyEntity.class,new AssistantBudgetDailyEntity.Id(ORG,bucket));
  var user=records.find(AssistantBudgetDailyEntity.class,new AssistantBudgetDailyEntity.Id(AssistantPersistence.ownerKey(owner),bucket));
  AssistantSettings.Features.Slice slice;
  try{slice=slice(cfg,feature);}catch(IllegalStateException e){return false;}
  var sliceRow=slice==null?null:records.find(AssistantBudgetDailyEntity.class,new AssistantBudgetDailyEntity.Id(featureScope(feature.key()),bucket));
  return fits(org,cfg.orgDailyTokens(),cfg.orgDailyCostMicros(),tokens,cost)&&fits(user,cfg.userDailyTokens(),cfg.userDailyCostMicros(),tokens,cost)
    &&(slice==null||fits(sliceRow,slice.dailyTokens(),slice.dailyCostMicros(),tokens,cost));
 }
 /**
  * Which daily limit one worst-case request would pass, in words for the person who asked, or null when
  * it fits. The same checks as {@link #canAfford}; one generic "budget used up" hid that the cap hit
  * was a person's token limit while the page showed only cost.
  */
 public String shortfall(String owner,AssistantSettings cfg,AssistantSettings.Model model,long inputUpperBound,long outputUpperBound,AssistantFeature feature){
  long tokens=inputUpperBound+outputUpperBound,cost=model.cost(inputUpperBound,outputUpperBound);
  long bucket=LocalDate.now(ZoneOffset.UTC).atStartOfDay(ZoneOffset.UTC).toInstant().toEpochMilli();
  var org=records.find(AssistantBudgetDailyEntity.class,new AssistantBudgetDailyEntity.Id(ORG,bucket));
  var user=records.find(AssistantBudgetDailyEntity.class,new AssistantBudgetDailyEntity.Id(AssistantPersistence.ownerKey(owner),bucket));
  AssistantSettings.Features.Slice slice;
  try{slice=slice(cfg,feature);}catch(IllegalStateException e){return "this feature has no daily share set";}
  var sliceRow=slice==null?null:records.find(AssistantBudgetDailyEntity.class,new AssistantBudgetDailyEntity.Id(featureScope(feature.key()),bucket));
  if(!fits(user,cfg.userDailyTokens(),Long.MAX_VALUE,tokens,0))return "your daily token limit ("+String.format(Locale.ROOT,"%,d",cfg.userDailyTokens())+" tokens)";
  if(!fits(user,Long.MAX_VALUE,cfg.userDailyCostMicros(),0,cost))return "your daily cost limit";
  if(!fits(org,cfg.orgDailyTokens(),Long.MAX_VALUE,tokens,0))return "the organization's daily token limit ("+String.format(Locale.ROOT,"%,d",cfg.orgDailyTokens())+" tokens)";
  if(!fits(org,Long.MAX_VALUE,cfg.orgDailyCostMicros(),0,cost))return "the organization's daily cost limit";
  if(slice!=null&&!fits(sliceRow,slice.dailyTokens(),slice.dailyCostMicros(),tokens,cost))return "this feature's daily share";
  return null;
 }
 /** The sentence for a refusal, naming the limit and where it is changed. */
 public static String limitMessage(AssistantFeature feature,String shortfall){
  return "The daily AI limit for "+feature.label().toLowerCase(Locale.ROOT)+" is reached: "+(shortfall==null?"a daily limit":shortfall)+". Try again tomorrow, or ask an admin to raise it under AI assistant settings > Limits.";
 }
 /** What one feature's slice has been charged today (UTC), including open reservations. */
 public Map<String,Long> usedToday(AssistantFeature feature){
  long bucket=LocalDate.now(ZoneOffset.UTC).atStartOfDay(ZoneOffset.UTC).toInstant().toEpochMilli();
  var row=records.find(AssistantBudgetDailyEntity.class,new AssistantBudgetDailyEntity.Id(featureScope(feature.key()),bucket));
  return Map.of("tokens",row==null?0L:row.chargedTokens,"cost_micros",row==null?0L:row.chargedCostMicros);
 }
 /** Today's charged usage (UTC day), including reservations not yet settled, for the settings page. */
 public Map<String,Long> today(String owner){
  long bucket=LocalDate.now(ZoneOffset.UTC).atStartOfDay(ZoneOffset.UTC).toInstant().toEpochMilli();
  var org=records.find(AssistantBudgetDailyEntity.class,new AssistantBudgetDailyEntity.Id(ORG,bucket));
  var user=records.find(AssistantBudgetDailyEntity.class,new AssistantBudgetDailyEntity.Id(AssistantPersistence.ownerKey(owner),bucket));
  return Map.of("org_tokens",org==null?0L:org.chargedTokens,"org_cost_micros",org==null?0L:org.chargedCostMicros,
    "user_tokens",user==null?0L:user.chargedTokens,"user_cost_micros",user==null?0L:user.chargedCostMicros);
 }
 private static boolean fits(AssistantBudgetDailyEntity row,long tokenCap,long costCap,long tokens,long cost){
  long usedTokens=row==null?0:row.chargedTokens,usedCost=row==null?0:row.chargedCostMicros;
  return usedTokens+tokens<=tokenCap&&usedCost+cost<=costCap;
 }
 /** What the owner has been charged today (UTC), including open reservations, in cost micros. */
 public long usedTodayMicros(String owner){
  long bucket=LocalDate.now(ZoneOffset.UTC).atStartOfDay(ZoneOffset.UTC).toInstant().toEpochMilli();
  var row=records.find(AssistantBudgetDailyEntity.class,new AssistantBudgetDailyEntity.Id(AssistantPersistence.ownerKey(owner),bucket));
  return row==null?0:row.chargedCostMicros;
 }
 /** Returns the unused part of a direct charge; uncertain usage stays charged by not calling this. */
 public void settleDirect(Charge c,long actualTokens,long actualCost){
  if(actualTokens<0||actualCost<0||actualTokens>c.tokens()||actualCost>c.cost())throw new IllegalStateException("PROVIDER_USAGE_EXCEEDS_RESERVATION");
  tx.executeWithoutResult(s->{
   records.lock(AssistantSettingsEntity.class,1);
   var rows=new ArrayList<AssistantBudgetDailyEntity>(List.of(bucket(ORG,c.bucket())));
   if(c.feature()!=null)rows.add(bucket(featureScope(c.feature()),c.bucket()));
   rows.add(bucket(c.user(),c.bucket()));
   for(var row:rows){row.chargedTokens-=c.tokens()-actualTokens;row.chargedCostMicros-=c.cost()-actualCost;}
  });
 }
 public void settle(AssistantPersistence.Turn turn,Reservation r,long actualTokens,long actualCost){
  if(actualTokens<0||actualCost<0||actualTokens>r.tokens()||actualCost>r.cost())throw new IllegalStateException("PROVIDER_USAGE_EXCEEDS_RESERVATION");
  tx.executeWithoutResult(s->{
   records.lock(AssistantSettingsEntity.class,1);
   var organization=bucket(ORG,r.bucket());var sliceBucket=r.feature()==null?null:bucket(featureScope(r.feature()),r.bucket());var individual=bucket(r.user(),r.bucket());
   var current=records.lock(AssistantTurnEntity.class,turn.id());
   var reservation=records.lock(AssistantRequestReservationEntity.class,r.id());
   if(reservation==null||reservation.actualTokens!=null)return;
   if(!Objects.equals(reservation.turnId,turn.id())||!Objects.equals(reservation.ownerScope,r.user())||reservation.bucketStart!=r.bucket()||reservation.reservedTokens!=r.tokens()||reservation.reservedCostMicros!=r.cost()||!Objects.equals(reservation.feature,r.feature()))throw new IllegalArgumentException("Reservation mismatch");
   reservation.actualTokens=actualTokens;reservation.actualCostMicros=actualCost;
   long tokens=r.tokens()-actualTokens,cost=r.cost()-actualCost;
   var buckets=new ArrayList<>(List.of(organization,individual));if(sliceBucket!=null)buckets.add(sliceBucket);
   for(var bucket:buckets){bucket.chargedTokens-=tokens;bucket.chargedCostMicros-=cost;}
   if(current==null)throw new IllegalStateException("TURN_MISSING");
   current.tokens-=tokens;current.costMicros-=cost;
  });
 }
}
