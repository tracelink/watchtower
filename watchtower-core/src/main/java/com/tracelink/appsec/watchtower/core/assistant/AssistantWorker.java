package com.tracelink.appsec.watchtower.core.assistant;

import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import jakarta.annotation.PreDestroy;
import org.springframework.stereotype.Component;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.event.EventListener;
import org.springframework.scheduling.annotation.Scheduled;

/**
 * Dedicated lane; neither scan pause nor repository queue capacity controls assistant turns.
 * Accepted turns wake this pod after commit and shared JPA claims fence competing pods, so chat
 * needs no queue. Periodic recovery picks up missed wake-ups and leases abandoned by stopped pods.
 */
@Component
public class AssistantWorker {
 private static final org.slf4j.Logger LOG=org.slf4j.LoggerFactory.getLogger(AssistantWorker.class);
 private final AssistantPersistence db;private final AssistantSettingsService settings;private final AssistantTurnRunner runner;
 private final ExecutorService pool;private final ExecutorService dispatcher=Executors.newSingleThreadExecutor();private final ScheduledExecutorService heartbeats=Executors.newSingleThreadScheduledExecutor();
 private final Semaphore slots;private final Set<String> local=ConcurrentHashMap.newKeySet();private final AtomicBoolean requested=new AtomicBoolean();private final String worker=UUID.randomUUID().toString();
 public AssistantWorker(AssistantPersistence db,AssistantSettingsService settings,AssistantTurnRunner runner,@Value("${watchtower.assistant.workers:2}")int workers){
  if(workers<1||workers>8)throw new IllegalArgumentException("Assistant workers must be 1–8");this.db=db;this.settings=settings;this.runner=runner;slots=new Semaphore(workers);pool=Executors.newFixedThreadPool(workers);
 }
 @EventListener public void accepted(AssistantPersistence.Accepted turn){wake();}
 @Scheduled(fixedDelayString="${watchtower.assistant.recovery-delay-ms:5000}") public void recover(){wake();}
 /** Coalesces wake-ups onto one dispatcher thread; a wake during a drain schedules one more drain. */
 public void wake(){
  if(!requested.compareAndSet(false,true))return;
  try{dispatcher.execute(()->{requested.set(false);drain();});}catch(RejectedExecutionException e){requested.set(false);}
 }
 private void drain(){
  try{
   if(!settings.available()||slots.availablePermits()==0)return;
   for(String id:db.claimable(slots.availablePermits()+local.size())){
    if(local.contains(id))continue;if(!slots.tryAcquire())return;local.add(id);
    try{pool.execute(()->run(id));}catch(RejectedExecutionException e){local.remove(id);slots.release();return;}
   }
  }catch(RuntimeException e){LOG.warn("Assistant dispatch failed; periodic recovery will retry",e);}
 }
 private void run(String id){ScheduledFuture<?> beat=null;
  try{var claim=db.claim(id,worker);if(claim.isEmpty())return;var t=claim.get();
   beat=heartbeats.scheduleAtFixedRate(()->{try{db.heartbeat(t);}catch(RuntimeException ignored){}},20,20,TimeUnit.SECONDS);
   runner.run(t);
  }catch(RuntimeException e){LOG.warn("Assistant turn claim failed; periodic recovery will retry",e);}
  // A freed slot drains pending turns immediately instead of waiting for periodic recovery.
  finally{if(beat!=null)beat.cancel(false);local.remove(id);slots.release();wake();}
 }
 @PreDestroy public void close(){dispatcher.shutdownNow();pool.shutdownNow();heartbeats.shutdownNow();}
}
