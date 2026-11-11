package com.tracelink.appsec.watchtower.core.scan.apiintegration.webhook;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import com.tracelink.appsec.watchtower.core.persistence.LedgerRepository;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.*;
import com.tracelink.appsec.watchtower.core.scan.code.scm.api.bb.*;
import kong.unirest.json.*;

/** Short JPA transactions only. Remote calls never run while a database lock is held. */
@Service
@Transactional
public class BBWebhookStore {
    private final LedgerRepository records;
    private final ApiIntegrationRepository integrations;
    /** Outcomes of a refused change: they fail the task but say nothing about the last saved read of the scope. */
    private static final java.util.Set<String> TASK_ONLY_FAILURES=java.util.Set.of("SELECTION_OR_OWNERSHIP_CHANGED","CONFIGURATION_CHANGED","LIMIT");
    public BBWebhookStore(LedgerRepository records, ApiIntegrationRepository integrations) {
        this.records=records; this.integrations=integrations;
    }
    public record ScopeView(String scope, List<BBCloudWebhook> hooks, Long checkedAt, Long attemptedAt,
            String error, boolean stale, String changedBy, Long changedAt) { }
    public record TaskView(String scope, String status, String result) { }
    public record OperationView(String id, Long jobId, String action, String status, long createdAt,
            String actor, long total, long finished, long failed, List<TaskView> tasks) { }
    public record RotationView(boolean pending, String operationId, Long previousAcceptedUntil) { }
    public BBCloudIntegrationEntity integration(String label) {
        var entity=integrations.findByApiLabel(label);
        if (!(entity instanceof BBCloudIntegrationEntity bb)) throw new IllegalArgumentException("Bitbucket integration not found");
        return bb;
    }
    public void saveSettings(BBCloudIntegrationEntity incoming) {
        var saved=records.lock(BBCloudIntegrationEntity.class,incoming.getIntegrationId());
        if(saved==null)throw new IllegalArgumentException("Bitbucket integration not found");
        assertIdle(saved.getIntegrationId());
        if(saved.getWebhookSecret()!=null&&!Objects.equals(saved.getWebhookSecret(),incoming.getWebhookSecret()))
            throw new IllegalArgumentException("Use Rotate secret on the Webhooks page to change the signing secret");
        Long owned=records.scalar(Long.class,"SELECT sum(s.ownedCount) FROM BBWebhookScopeEntity s WHERE s.integrationId=?1",saved.getIntegrationId());
        if(!Objects.equals(saved.getWorkspace(),incoming.getWorkspace())&&(saved.getWebhookUuid()!=null||(owned!=null&&owned>0)))
            throw new IllegalArgumentException("Remove owned webhooks before changing the workspace");
        saved.setWorkspace(incoming.getWorkspace());saved.setUser(incoming.getUser());saved.setAuth(incoming.getAuth());saved.setRejectOption(incoming.getRejectOption());
        if(saved.getWebhookSecret()==null)saved.setWebhookSecret(incoming.getWebhookSecret());
    }
    public void assertIdle(long id) {
        records.lock(BBCloudIntegrationEntity.class,id);
        long busy=records.scalar(Long.class,"SELECT count(o) FROM BBWebhookOperationEntity o WHERE o.integrationId=?1 AND o.status IN ('QUEUED','RUNNING')",id);
        var c=records.find(BBWebhookControlEntity.class,id);
        if(busy>0||(c!=null&&c.rotationOperation!=null))throw new IllegalStateException("Wait for webhook operations, or resume the pending rotation first");
    }
    public void assertDeletable(long id) {
        assertIdle(id);Long owned=records.scalar(Long.class,"SELECT sum(s.ownedCount) FROM BBWebhookScopeEntity s WHERE s.integrationId=?1",id);
        if(owned!=null&&owned>0)throw new IllegalStateException("Remove owned webhooks before deleting the integration");
    }
    public long knownRepoCount(long id,String hash) {
        return records.scalar(Long.class,"SELECT count(s) FROM BBWebhookScopeEntity s WHERE s.integrationId=?1 AND s.scope<>'' AND s.checkedAt IS NOT NULL AND s.callbackHash=?2",id,hash);
    }
    public long ownedRepositories(long id,String hash) {
        return records.scalar(Long.class,"SELECT count(s) FROM BBWebhookScopeEntity s WHERE s.integrationId=?1 AND s.scope<>'' AND s.ownedCount>0 AND s.callbackHash=?2",id,hash);
    }
    public BBCloudIntegrationEntity prepare(String label) {
        var bb=integration(label);
        bb=records.lock(BBCloudIntegrationEntity.class,bb.getIntegrationId());
        if (bb.getRegisterState()==RegisterState.IN_PROGRESS) throw new IllegalStateException("Workspace registration is still in progress");
        new BBCloudApi(bb).ensureWebhookSecret();
        if (records.find(BBWebhookControlEntity.class,bb.getIntegrationId())==null) {
            var control=new BBWebhookControlEntity(); control.id=bb.getIntegrationId(); records.insert(control);
        }
        return bb;
    }
    public BBWebhookOperationEntity create(String label,String action,BBWebhookPreset preset,boolean active,
            String actor,Map<String,String> scopes) {
        var bb=prepare(label);
        var control=records.find(BBWebhookControlEntity.class,bb.getIntegrationId());
        if (control.rotationOperation!=null && !action.equals("SYNC")) throw new IllegalStateException("Resume the pending secret rotation first");
        if (action.equals("ROTATE") && bb.getPreviousWebhookSecretUntil()!=null && bb.getPreviousWebhookSecretUntil()>System.currentTimeMillis())
            throw new IllegalStateException("Wait until the previous secret's transition window ends before rotating again");
        var op=new BBWebhookOperationEntity(); op.id=UUID.randomUUID().toString(); op.integrationId=bb.getIntegrationId();
        op.action=action; op.workspace=bb.getWorkspace(); op.preset=preset.name(); op.active=active; op.actor=actor; op.createdAt=System.currentTimeMillis(); op.status="QUEUED";
        records.insert(op);
        scopes.forEach((scope,uuid)->{var task=new BBWebhookTaskEntity(); task.id=UUID.randomUUID().toString(); task.operationId=op.id;
            task.scope=scope; task.hookUuid=uuid; task.status="PENDING"; records.insert(task);});
        return op;
    }
    public List<BBWebhookOperationEntity> unpublished() {
        return records.list(BBWebhookOperationEntity.class,"SELECT o FROM BBWebhookOperationEntity o WHERE o.jobId IS NULL AND o.status='QUEUED' AND o.createdAt<?1",0,50,System.currentTimeMillis()-60000);
    }
    public String workerLabel(long id) {
        var bb=records.find(BBCloudIntegrationEntity.class,id);if(bb==null)throw new IllegalArgumentException("Integration not found");return bb.getApiLabel();
    }
    public void configureOperation(String id,String callbackHash) {
        var op=operation(id);if(op.callbackHash==null)op.callbackHash=callbackHash;
    }
    public void deleteIntegration(long id) {
        assertDeletable(id);var bb=records.lock(BBCloudIntegrationEntity.class,id);
        if(bb==null)throw new IllegalArgumentException("Integration not found");records.remove(bb);
        var control=records.find(BBWebhookControlEntity.class,id);if(control!=null)records.remove(control);
    }
    public void queued(String id,Long jobId) {
        var op=records.find(BBWebhookOperationEntity.class,id); op.jobId=jobId; if(jobId==null&&!op.status.equals("DONE"))op.status="QUEUE_FAILED";
    }
    public BBWebhookOperationEntity operation(String id) {
        var op=records.find(BBWebhookOperationEntity.class,id); if(op==null)throw new IllegalArgumentException("Webhook operation not found"); return op;
    }
    public boolean finished(String id) {
        return records.scalar(String.class,"SELECT o.status FROM BBWebhookOperationEntity o WHERE o.id=?1",id).equals("DONE");
    }
    public List<BBWebhookTaskEntity> pending(String id) {
        return records.list(BBWebhookTaskEntity.class,"SELECT t FROM BBWebhookTaskEntity t WHERE t.operationId=?1 AND t.status='PENDING' ORDER BY t.scope",0,25,id);
    }
    public List<String> knownScopes(long integrationId) {
        return records.list(String.class,"SELECT s.scope FROM BBWebhookScopeEntity s WHERE s.integrationId=?1 AND s.scope<>'' ORDER BY s.scope",0,100000,integrationId);
    }
    public boolean claim(String opId,String owner) {
        var op=operation(opId); var bb=records.lock(BBCloudIntegrationEntity.class,op.integrationId);
        if(bb==null)throw new IllegalArgumentException("Integration was deleted");
        // A duplicate job published after completion must never start a second rotation.
        if(records.scalar(String.class,"SELECT o.status FROM BBWebhookOperationEntity o WHERE o.id=?1",opId).equals("DONE"))return false;
        var c=records.lock(BBWebhookControlEntity.class,op.integrationId); long now=System.currentTimeMillis();
        if(c.owner!=null && !c.owner.equals(owner) && c.leaseUntil>now)return false;
        c.owner=owner;c.leaseUntil=now+180000; op.status="RUNNING";return true;
    }
    public void assertOwner(String opId,String owner) {
        var c=records.lock(BBWebhookControlEntity.class,operation(opId).integrationId);
        if(c==null || !owner.equals(c.owner) || c.leaseUntil<System.currentTimeMillis())throw new IllegalStateException("Webhook operation lease was lost");
        c.leaseUntil=System.currentTimeMillis()+180000;
    }
    public void release(String opId,String owner) {
        var c=records.lock(BBWebhookControlEntity.class,operation(opId).integrationId);
        if(c!=null && owner.equals(c.owner)){c.owner=null;c.leaseUntil=0;}
    }
    public BBCloudIntegrationEntity workerIntegration(String opId,String owner) {
        assertOwner(opId,owner); return records.find(BBCloudIntegrationEntity.class,operation(opId).integrationId);
    }
    public void beginRotation(String opId,String owner) {
        assertOwner(opId,owner);var op=operation(opId);var c=records.lock(BBWebhookControlEntity.class,op.integrationId);
        var bb=records.lock(BBCloudIntegrationEntity.class,op.integrationId);
        if(c.rotationOperation==null) {
            c.rotationSecret=BBWebhookSecrets.generate(); c.rotationOperation=opId; c.rotationStartedAt=System.currentTimeMillis();
            bb.setPreviousWebhookSecret(bb.getWebhookSecret()); bb.setWebhookSecret(c.rotationSecret); bb.setPreviousWebhookSecretUntil(c.rotationStartedAt+86400000L);
        } else if(!opId.equals(c.rotationOperation))throw new IllegalStateException("Another secret rotation is pending");
        if(bb.getPreviousWebhookSecretUntil()==null)bb.setPreviousWebhookSecretUntil(c.rotationStartedAt+86400000L);
    }
    public void abort(String opId,String owner) {
        var op=operation(opId);var c=records.lock(BBWebhookControlEntity.class,op.integrationId);
        if(c==null||!owner.equals(c.owner))return;
        records.update("UPDATE BBWebhookTaskEntity t SET t.status='FAILED',t.result='INTERRUPTED',t.finishedAt=?2 WHERE t.operationId=?1 AND t.status='PENDING'",opId,System.currentTimeMillis());
        op=records.find(BBWebhookOperationEntity.class,opId);op.status="PARTIAL_FAILURE";
    }
    public void finish(String opId,String owner) {
        assertOwner(opId,owner);var op=operation(opId);
        long failures=records.scalar(Long.class,"SELECT count(t) FROM BBWebhookTaskEntity t WHERE t.operationId=?1 AND t.status='FAILED'",opId);
        op.status=failures==0?"DONE":"PARTIAL_FAILURE";
        if(op.action.equals("ROTATE") && failures==0) {
            var c=records.lock(BBWebhookControlEntity.class,op.integrationId); c.rotationOperation=null;c.rotationSecret=null;c.rotationStartedAt=null;
            var bb=records.lock(BBCloudIntegrationEntity.class,op.integrationId); bb.setPreviousWebhookSecretUntil(Math.min(bb.getPreviousWebhookSecretUntil()==null?0:bb.getPreviousWebhookSecretUntil(),System.currentTimeMillis()+600000));
        }
    }
    public void retry(String opId) {
        var op=operation(opId);records.lock(BBCloudIntegrationEntity.class,op.integrationId);
        if(!Set.of("PARTIAL_FAILURE","QUEUE_FAILED").contains(op.status))throw new IllegalStateException("This operation has no retryable failures");
        var c=records.find(BBWebhookControlEntity.class,op.integrationId);
        if(c.rotationOperation!=null && !opId.equals(c.rotationOperation))throw new IllegalStateException("Resume the pending secret rotation first");
        records.update("UPDATE BBWebhookTaskEntity t SET t.status='PENDING',t.result=null,t.finishedAt=null WHERE t.operationId=?1 AND t.status='FAILED'",opId);
        op=records.find(BBWebhookOperationEntity.class,opId);op.status="QUEUED";
    }
    public void snapshot(String opId,String owner,String taskId,List<BBCloudWebhook> hooks,String callbackHash,String result) {
        assertOwner(opId,owner);var op=operation(opId);var task=records.find(BBWebhookTaskEntity.class,taskId);
        var scope=scope(op.integrationId,task.scope,true);long now=System.currentTimeMillis();
        scope.hooksJson=encode(hooks);scope.checkedAt=now;scope.attemptedAt=now;scope.error=null;scope.callbackHash=callbackHash;
        scope.ownedCount=(int)hooks.stream().filter(BBCloudWebhook::owned).count();
        scope.activeOwnedCount=(int)hooks.stream().filter(h->h.owned()&&h.active()).count();
        if(!op.action.equals("SYNC")){scope.changedAt=now;scope.changedBy=op.actor;}
        task.status="DONE";task.result=result;task.finishedAt=now;
        if(task.scope.isEmpty()) {
            var bb=records.lock(BBCloudIntegrationEntity.class,op.integrationId);
            bb.setWebhookUuid(hooks.stream().filter(BBCloudWebhook::owned).map(BBCloudWebhook::uuid).findFirst().orElse(null));
            bb.setRegisterState(scope.ownedCount>0?RegisterState.REGISTERED:RegisterState.NOT_REGISTERED);bb.setRegisterError(null);
        }
    }
    public void failure(String opId,String owner,String taskId,String code,boolean retryLater) {
        assertOwner(opId,owner);var op=operation(opId);var task=records.find(BBWebhookTaskEntity.class,taskId);
        var scope=scope(op.integrationId,task.scope,true);scope.attemptedAt=System.currentTimeMillis();
        // A refused change is the task's outcome only; the saved snapshot is still good. Provider failures mark the scope.
        if(!TASK_ONLY_FAILURES.contains(code))scope.error=code;
        if(!retryLater){task.status="FAILED";task.result=code;task.finishedAt=System.currentTimeMillis();}
    }
    private BBWebhookScopeEntity scope(long id,String key,boolean create) {
        var rows=records.list(BBWebhookScopeEntity.class,"SELECT s FROM BBWebhookScopeEntity s WHERE s.integrationId=?1 AND s.scope=?2",0,1,id,key);
        if(!rows.isEmpty())return rows.getFirst(); if(!create)return null;
        var s=new BBWebhookScopeEntity();s.id=UUID.randomUUID().toString();s.integrationId=id;s.scope=key;s.hooksJson="[]";records.insert(s);return s;
    }
    public ScopeView scopeView(long id,String key,String hash) {return view(scope(id,key,false),key,hash);}
    public List<ScopeView> scopes(long id,String search,int page,String hash) {
        return records.list(BBWebhookScopeEntity.class,"SELECT s FROM BBWebhookScopeEntity s WHERE s.integrationId=?1 AND s.scope<>'' AND lower(s.scope) LIKE ?2 ORDER BY s.scope",Math.max(0,page)*20,20,id,"%"+search.toLowerCase(Locale.ROOT)+"%").stream().map(s->view(s,s.scope,hash)).toList();
    }
    public long scopeCount(long id,String search) {
        return records.scalar(Long.class,"SELECT count(s) FROM BBWebhookScopeEntity s WHERE s.integrationId=?1 AND s.scope<>'' AND lower(s.scope) LIKE ?2",id,"%"+search.toLowerCase(Locale.ROOT)+"%");
    }
    private ScopeView view(BBWebhookScopeEntity s,String key,String hash) {
        if(s==null)return new ScopeView(key,List.of(),null,null,null,true,null,null);
        boolean stale=s.checkedAt==null||s.checkedAt<System.currentTimeMillis()-86400000L||!hash.equals(s.callbackHash);
        // A callback configuration change invalidates old ownership claims.
        var hooks=decode(s.hooksJson);if(!hash.equals(s.callbackHash))hooks=hooks.stream().map(h->new BBCloudWebhook(h.uuid(),h.urlHostPath(),h.events(),h.active(),false,h.secretSet())).toList();
        return new ScopeView(key,hooks,s.checkedAt,s.attemptedAt,s.error,stale,s.changedBy,s.changedAt);
    }
    public long ownedRepoCount(long id,String hash) {
        Long n=records.scalar(Long.class,"SELECT sum(s.ownedCount) FROM BBWebhookScopeEntity s WHERE s.integrationId=?1 AND s.scope<>'' AND s.callbackHash=?2",id,hash);return n==null?0:n;
    }
    public RotationView rotation(long id) {
        var c=records.find(BBWebhookControlEntity.class,id);var bb=records.find(BBCloudIntegrationEntity.class,id);
        return new RotationView(c!=null&&c.rotationOperation!=null,c==null?null:c.rotationOperation,bb.getPreviousWebhookSecretUntil());
    }
    public List<OperationView> recent(long id) {
        return records.list(BBWebhookOperationEntity.class,"SELECT o FROM BBWebhookOperationEntity o WHERE o.integrationId=?1 ORDER BY o.createdAt DESC",0,10,id).stream().map(o->operationView(o.id,0)).toList();
    }
    public OperationView operationView(String id,int page) {
        var o=operation(id);var tasks=records.list(BBWebhookTaskEntity.class,"SELECT t FROM BBWebhookTaskEntity t WHERE t.operationId=?1 ORDER BY t.scope",Math.max(0,page)*50,50,id).stream().map(t->new TaskView(t.scope,t.status,t.result)).toList();
        long total=records.scalar(Long.class,"SELECT count(t) FROM BBWebhookTaskEntity t WHERE t.operationId=?1",id);
        long pending=records.scalar(Long.class,"SELECT count(t) FROM BBWebhookTaskEntity t WHERE t.operationId=?1 AND t.status='PENDING'",id);
        long failed=records.scalar(Long.class,"SELECT count(t) FROM BBWebhookTaskEntity t WHERE t.operationId=?1 AND t.status='FAILED'",id);
        return new OperationView(o.id,o.jobId,o.action,o.status,o.createdAt,o.actor,total,total-pending,failed,tasks);
    }
    public static String hash(String value) {
        try {return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8)));}
        catch(Exception e){throw new IllegalStateException("Cannot hash webhook settings");}
    }
    static String encode(List<BBCloudWebhook> hooks) {
        var array=new JSONArray();for(var h:hooks)array.put(new JSONObject().put("uuid",h.uuid()).put("urlHostPath",h.urlHostPath()).put("events",new JSONArray(h.events())).put("active",h.active()).put("owned",h.owned()).put("secretSet",h.secretSet()));return array.toString();
    }
    static List<BBCloudWebhook> decode(String json) {
        var array=new JSONArray(json);var result=new ArrayList<BBCloudWebhook>();for(int i=0;i<array.length();i++){var h=array.getJSONObject(i);var events=new ArrayList<String>();var a=h.getJSONArray("events");for(int j=0;j<a.length();j++)events.add(a.getString(j));result.add(new BBCloudWebhook(h.getString("uuid"),h.getString("urlHostPath"),events,h.getBoolean("active"),h.getBoolean("owned"),h.getBoolean("secretSet")));}return List.copyOf(result);
    }
}
