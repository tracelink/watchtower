package com.tracelink.appsec.watchtower.core.assistant;

import java.io.IOException;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import jakarta.annotation.PreDestroy;
import org.springframework.stereotype.Component;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

/**
 * Bounded SSE delivery of durable turn progress and final answers. Every pod reads the same JPA
 * turn rows and transcript checkpoints, so a stream works wherever the request is routed; the
 * drawer falls back to polling when a stream is refused or drops. Provider tokens are not streamed.
 */
@Component
public class AssistantStreams {
 /** Transport boundary; SSE in production, a collecting fake in tests. */
 public interface Sink {void send(String event,Object data)throws IOException;void keepAlive()throws IOException;void complete();}
 static final class Stream {
  final String id,owner;final Sink sink;final AtomicBoolean closed=new AtomicBoolean();String seen;long checked,active;volatile ScheduledFuture<?> task;
  Stream(String id,String owner,Sink sink){this.id=id;this.owner=owner;this.sink=sink;}
 }
 private static final Set<String> TERMINAL=Set.of("COMPLETED","FAILED","CANCELED");
 /** {@code opinion}: for the assessment tool, whether an AI assessment was actually returned; absent for every other step. */
 @com.fasterxml.jackson.annotation.JsonInclude(com.fasterxml.jackson.annotation.JsonInclude.Include.NON_NULL)
 public record Activity(String tool,String status,Boolean opinion) {
  public Activity(String tool,String status){this(tool,status,null);}
 }
 private static final long KEEPALIVE_MILLIS=15000;
 /** One user cannot hold the shared stream capacity; extra tabs fall back to polling. */
 private static final int PER_OWNER=3;
 /** A stalled client blocks a tick thread inside its write until the emitter times out. */
 private static final int TICK_THREADS=8;
 private final AssistantPersistence db;private final AssistantAccess access;private final AssistantToolRegistry tools;
 private final Semaphore streams;private final Map<String,Integer> owners=new ConcurrentHashMap<>();private final long interval,recheck,timeout;private final ScheduledExecutorService ticks;
 public AssistantStreams(AssistantPersistence db,AssistantAccess access,AssistantToolRegistry tools,
  @Value("${watchtower.assistant.max-streams:64}")int max,@Value("${watchtower.assistant.stream-interval-ms:1000}")long interval,
  @Value("${watchtower.assistant.stream-recheck-ms:5000}")long recheck,@Value("${watchtower.assistant.stream-timeout-ms:600000}")long timeout){
  if(max<1||max>512||interval<100||recheck<0||timeout<1000)throw new IllegalArgumentException("Invalid assistant stream limits");
  this.db=db;this.access=access;this.tools=tools;this.streams=new Semaphore(max);this.interval=interval;this.recheck=recheck;this.timeout=timeout;ticks=Executors.newScheduledThreadPool(Math.min(TICK_THREADS,max));
 }
 /** Current authorized view; rechecks the kill switch, grants, ownership, expiry and evidence. */
 public Map<String,Object> view(String id,String owner)throws IOException{require(owner);var t=db.turn(id);db.own(t,owner);return render(t,owner);}
 public SseEmitter open(String id,String owner)throws IOException{
  var emitter=new SseEmitter(timeout);
  var stream=start(id,owner,new Sink(){
   @Override public void send(String event,Object data)throws IOException{emitter.send(SseEmitter.event().name(event).data(data,MediaType.APPLICATION_JSON));}
   @Override public void keepAlive()throws IOException{emitter.send(SseEmitter.event().comment("keepalive"));}
   @Override public void complete(){emitter.complete();}
  });
  emitter.onCompletion(()->close(stream));emitter.onTimeout(()->close(stream));emitter.onError(e->close(stream));return emitter;
 }
 Stream start(String id,String owner,Sink sink)throws IOException{
  require(owner);var t=db.turn(id);db.own(t,owner);
  // Capacity before rendering: a refused stream never pays for transcript reads or evidence replay.
  if(!acquire(owner))throw new ResponseStatusException(HttpStatus.TOO_MANY_REQUESTS,"Progress streams are busy; polling continues");
  var stream=new Stream(id,owner,sink);
  synchronized(stream){
   stream.seen=signature(t);stream.checked=stream.active=System.currentTimeMillis();
   try{sink.send("turn",render(t,owner));}catch(IOException|RuntimeException e){close(stream);throw e;}
   if(TERMINAL.contains(t.status()))close(stream);else stream.task=ticks.scheduleWithFixedDelay(()->tick(stream),interval,interval,TimeUnit.MILLISECONDS);
  }
  return stream;
 }
 /** Reads only the turn row unless it changed or a periodic access recheck is due. */
 void tick(Stream stream){
  synchronized(stream){
   if(stream.closed.get()){var task=stream.task;if(task!=null)task.cancel(false);return;}long now=System.currentTimeMillis();
   try{
    var t=db.turn(stream.id);String signature=signature(t);
    if(!signature.equals(stream.seen)){
     authorize(t,stream.owner);stream.sink.send("turn",render(t,stream.owner));stream.seen=signature;stream.checked=stream.active=now;
     if(TERMINAL.contains(t.status()))close(stream);return;
    }
    if(now-stream.checked>=recheck){authorize(t,stream.owner);stream.checked=now;}
    if(now-stream.active>=KEEPALIVE_MILLIS){stream.sink.keepAlive();stream.active=now;}
   }catch(AccessDeniedException|ResponseStatusException e){end(stream);}
   // Client gone or transient storage/database failure: the browser reconnects or polls.
   catch(IOException|RuntimeException e){close(stream);}
  }
 }
 /** Kill switch and current grant come before any turn lookup, so revoked users learn nothing about ids. */
 private void require(String owner){db.enabled();access.require(owner,"Assistant Use");}
 private void authorize(AssistantPersistence.Turn t,String owner){require(owner);db.own(t,owner);}
 private Map<String,Object> render(AssistantPersistence.Turn t,String owner)throws IOException{
  var state=db.state(t);tools.replay(owner,state);
  var activity=new ArrayList<Activity>();state.activity.forEach(a->activity.add(new Activity(a.path("tool").asText(),a.path("status").asText(),a.has("opinion")?a.path("opinion").asBoolean():null)));
  Map<String,Object> response=new LinkedHashMap<>();response.put("turnId",t.id());response.put("sessionId",t.session());response.put("status",t.status());response.put("answer","COMPLETED".equals(t.status())?state.answer:null);response.put("activity",activity);response.put("error",t.error());response.put("model",t.model());response.put("effort",t.effort());response.put("tokens",t.tokens());response.put("costMicros",t.cost());response.put("expiresAt",db.session(t.session(),owner).get("expires_at"));
  if("COMPLETED".equals(t.status())){response.put("citations",citations(state));response.put("changeSets",changeSets(t,owner));}
  return response;
 }
 private static final int MAX_CITATIONS=8;
 /** Rules the turn's tools read successfully, by name; at most a few, in reading order. */
 private List<Map<String,Object>> citations(AssistantState state){
  var ids=new LinkedHashSet<Long>();state.activity.forEach(a->{if(a.path("rule").canConvertToLong()&&ids.size()<MAX_CITATIONS)ids.add(a.path("rule").asLong());});
  if(ids.isEmpty())return List.of();
  var names=new HashMap<Long,Object>();db.records().maps("SELECT r.id AS id,r.name AS name FROM RuleEntity r WHERE r.id IN ?1",0,MAX_CITATIONS,new ArrayList<>(ids)).forEach(r->names.put(((Number)r.get("id")).longValue(),r.get("name")));
  var cited=new ArrayList<Map<String,Object>>();for(Long id:ids)if(names.containsKey(id))cited.add(Map.of("id",id,"name",names.get(id)));return cited;
 }
 /** Change sets this turn prepared for its owner; the drawer shows each as an approval card. */
 private List<Object> changeSets(AssistantPersistence.Turn t,String owner){
  return db.records().maps("SELECT c.id AS id FROM RulesetChangeSetEntity c WHERE c.turnId=?1 AND c.owner=?2 ORDER BY c.createdAt",0,5,t.id(),owner).stream().map(r->r.get("id")).toList();
 }
 private static String signature(AssistantPersistence.Turn t){return t.status()+"|"+t.checkpoint()+"|"+t.error();}
 /** Access ended: tell the client to stop reconnecting; its polling fallback reports why. */
 private void end(Stream stream){try{stream.sink.send("end",Map.of("status","closed"));}catch(IOException ignored){}close(stream);}
 private boolean acquire(String owner){
  if(!streams.tryAcquire())return false;boolean[] granted={false};
  owners.compute(owner,(k,n)->{int count=n==null?0:n;if(count>=PER_OWNER)return n;granted[0]=true;return count+1;});
  if(!granted[0])streams.release();return granted[0];
 }
 private void close(Stream stream){
  if(!stream.closed.compareAndSet(false,true))return;var task=stream.task;if(task!=null)task.cancel(false);
  owners.computeIfPresent(stream.owner,(k,n)->n<=1?null:n-1);streams.release();stream.sink.complete();
 }
 @PreDestroy public void close(){ticks.shutdownNow();}
}
