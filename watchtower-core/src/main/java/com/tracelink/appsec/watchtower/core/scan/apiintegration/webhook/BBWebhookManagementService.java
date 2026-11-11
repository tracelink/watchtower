package com.tracelink.appsec.watchtower.core.scan.apiintegration.webhook;

import java.util.*;
import java.util.function.Consumer;
import org.slf4j.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.domain.*;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import com.tracelink.appsec.watchtower.core.job.*;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.*;
import com.tracelink.appsec.watchtower.core.scan.code.CodeScanType;
import com.tracelink.appsec.watchtower.core.scan.code.scm.api.bb.*;
import com.tracelink.appsec.watchtower.core.scan.repository.*;

@Service
public class BBWebhookManagementService {
    private static final Logger LOG=LoggerFactory.getLogger(BBWebhookManagementService.class);
    private final BBWebhookStore store;
    private final RepositoryRepository repositories;
    private final AsyncJobService jobs;
    private final AsyncJobRepository jobRecords;
    private final String publicUrl;
    public BBWebhookManagementService(BBWebhookStore store,RepositoryRepository repositories,@org.springframework.context.annotation.Lazy AsyncJobService jobs,
            AsyncJobRepository jobRecords,@Value("${watchtower.publicUrl:#{null}}")String publicUrl) {
        this.store=store;this.repositories=repositories;this.jobs=jobs;this.jobRecords=jobRecords;this.publicUrl=publicUrl;
    }
    public void saveSettings(BBCloudIntegrationEntity incoming){store.saveSettings(incoming);}
    public void assertDeletable(long id){store.assertDeletable(id);}
    public void deleteIntegration(long id){store.deleteIntegration(id);}
    public void decorate(List<ApiIntegrationEntity> entities) {
        if(publicUrl==null||publicUrl.isBlank())return;
        for(var entity:entities)if(entity instanceof BBCloudIntegrationEntity bb && bb.getIntegrationId()>0) {
            String hash=callbackHash(bb.getApiLabel());
            var workspace=store.scopeView(bb.getIntegrationId(),"",hash);
            if(store.knownRepoCount(bb.getIntegrationId(),hash)>0)bb.setCachedWebhookRepositories(store.ownedRepositories(bb.getIntegrationId(),hash));
            // The last known state, even when it is old: dropping it made a hook nobody had re-checked read as "No active workspace hook"
            if(workspace.checkedAt()!=null)bb.setCachedWorkspaceActive(workspace.hooks().stream().anyMatch(h->h.owned()&&h.active()));
        }
    }
    public record PickerRepo(long id,String slug,boolean paused) { }
    public record Inventory(String label,BBWebhookStore.ScopeView workspace,List<BBWebhookStore.ScopeView> repositories,
            long total,int page,long ownedRepositoryHookCount,BBWebhookStore.RotationView rotation,List<BBWebhookStore.OperationView> operations) { }
    public String callbackHash(String label) {
        if(publicUrl==null||publicUrl.isBlank())throw new IllegalStateException("watchtower.publicUrl must be configured");
        return BBWebhookStore.hash(publicUrl.replaceAll("/+$","")+"/rest/scan/"+label);
    }
    public Inventory inventory(String label,String search,int page) {
        if(page<0||page>100000||search.length()>255)throw new IllegalArgumentException("Invalid inventory page or search");
        var bb=store.integration(label);String hash=callbackHash(bb.getApiLabel());
        return new Inventory(bb.getApiLabel(),store.scopeView(bb.getIntegrationId(),"",hash),
                store.scopes(bb.getIntegrationId(),search,page,hash),store.scopeCount(bb.getIntegrationId(),search),page,
                store.ownedRepoCount(bb.getIntegrationId(),hash),store.rotation(bb.getIntegrationId()),store.recent(bb.getIntegrationId()));
    }
    public List<BBCloudWebhook> live(String label,String slug) {
        var bb=store.integration(label);callbackHash(bb.getApiLabel());
        if(slug!=null){bb.makeRepoHooksUrl(slug);if(repositories.findByApiLabelAndRepoName(bb.getApiLabel(),slug)==null&&!store.knownScopes(bb.getIntegrationId()).contains(slug))throw new IllegalArgumentException("Repository not found in this integration");}
        try {var api=(BBCloudApi)bb.createApi();return slug==null?api.listWorkspaceHooks(publicUrl):api.listRepoHooks(slug,publicUrl);}
        catch(BBWebhookException e){throw e;}
        catch(RuntimeException e){throw new BBWebhookException(502,0);}
    }
    public Page<PickerRepo> picker(String label,String search,int page) {
        var bb=store.integration(label);
        if(page<0||page>100000||search.length()>255)throw new IllegalArgumentException("Invalid repository page or search");
        return repositories.findByScanTypeAndApiLabelAndEnabledTrueAndRepoNameContainingIgnoreCase(CodeScanType.PULL_REQUEST,bb.getApiLabel(),search,
                PageRequest.of(page,20,Sort.by("repoName"))).map(r->new PickerRepo(r.getId(),r.getRepoName(),r.isScanningPaused()));
    }
    public String refresh(String label,String repository,boolean workspaceOnly,String actor) {
        if(repository==null&&!workspaceOnly)return enqueue(label,"SYNC",BBWebhookPreset.ALL,true,List.of(),null,actor);
        var bb=store.integration(label);callbackHash(bb.getApiLabel());
        String scope=repository==null?"":repository;
        if(repository!=null) {
            bb.makeRepoHooksUrl(repository);
            if(repositories.findByApiLabelAndRepoName(bb.getApiLabel(),repository)==null&&!store.knownScopes(bb.getIntegrationId()).contains(repository))
                throw new IllegalArgumentException("Repository not found in this integration");
        }
        var selection=new TreeMap<String,String>();selection.put(scope,null);
        var op=store.create(bb.getApiLabel(),"SYNC",BBWebhookPreset.ALL,true,actor,selection);publish(op);return op.id;
    }
    public String enqueue(String label,String action,BBWebhookPreset preset,boolean active,List<String> slugs,String uuid,String actor) {
        var bb=store.integration(label);callbackHash(bb.getApiLabel());
        if(!Set.of("SYNC","UPSERT","DELETE","ROTATE").contains(action))throw new IllegalArgumentException("Invalid webhook action");
        var scopes=new TreeMap<String,String>();
        if(slugs==null) { scopes.put("",uuid); }
        else if(action.equals("SYNC")||action.equals("ROTATE")) {
            scopes.put("",null);
            // Include disabled and paused catalog entries: their already-existing hooks still need discovery and rotation.
            int page=0;Page<RepositoryEntity> batch;
            do {batch=repositories.findByScanTypeAndApiLabelAndRepoNameContainingIgnoreCase(CodeScanType.PULL_REQUEST,bb.getApiLabel(),"",PageRequest.of(page++,200,Sort.by("repoName")));
                batch.forEach(r->scopes.put(r.getRepoName(),null));}while(batch.hasNext());
            store.knownScopes(bb.getIntegrationId()).forEach(s->scopes.put(s,null));
        } else {
            if(slugs.isEmpty()||slugs.size()>500)throw new IllegalArgumentException("Choose between 1 and 500 repositories");
            for(String slug:slugs) {
                bb.makeRepoHooksUrl(slug);
                var repo=repositories.findByApiLabelAndRepoName(bb.getApiLabel(),slug);
                if(repo==null||repo.getScanType()!=CodeScanType.PULL_REQUEST||(!repo.isEnabled()&&action.equals("UPSERT")))throw new IllegalArgumentException("Choose enabled repositories from this integration");
                scopes.put(repo.getRepoName(),uuid);
            }
        }
        if(action.equals("DELETE") && (uuid==null||scopes.size()!=1))throw new IllegalArgumentException("Choose one owned hook to delete");
        var op=store.create(bb.getApiLabel(),action,preset==null?BBWebhookPreset.ALL:preset,active,actor,scopes);
        publish(op);return op.id;
    }
    private void publish(BBWebhookOperationEntity op) {
        var bb=store.workerLabel(op.integrationId);
        store.configureOperation(op.id,callbackHash(bb));
        String dedup="webhook:"+op.integrationId;
        var job=jobs.enqueue(op.action.equals("SYNC")?AsyncJobType.WEBHOOK_SYNC:AsyncJobType.WEBHOOK_BULK,op.id,dedup,op.actor);
        if(job.isPresent()){store.queued(op.id,job.get().getId());return;}
        var existing=jobRecords.findByDedupKey(dedup);
        if(existing!=null && op.id.equals(existing.getPayload())){store.queued(op.id,existing.getId());return;}
        store.queued(op.id,null);
        throw new IllegalStateException("Another webhook operation is active, or the job queue is unavailable. Retry this operation after it finishes.");
    }
    public BBWebhookStore.OperationView operation(String label,String id,int page) {
        var bb=store.integration(label);var op=store.operation(id);
        if(op.integrationId!=bb.getIntegrationId())throw new IllegalArgumentException("Webhook operation not found");
        if(page<0||page>100000)throw new IllegalArgumentException("Invalid outcomes page");
        return store.operationView(id,page);
    }
    public void retry(String label,String id,String actor) {
        operation(label,id,0);var previous=store.operation(id);
        if(previous.jobId!=null&&jobRecords.findById(previous.jobId).filter(j->!j.getStatus().isFinished()).isPresent())
            throw new IllegalStateException("The previous job is still finishing; retry shortly");
        store.retry(id);publish(store.operation(id));
        LOG.info("webhook user={} label={} operation={} action=retry result=queued",clean(actor),label,id);
    }
    /** Repair only the job publication gap; never automatically refresh Bitbucket. */
    @Scheduled(fixedDelayString="${watchtower.webhooks.recovery-ms:60000}")
    public void recoverPublication() {
        for(var op:store.unpublished())try{publish(op);}catch(RuntimeException ignored){/* Remains visible and retryable. */}
    }
    public String run(String operationId,Consumer<String> progress) {
        String owner=UUID.randomUUID().toString();
        if(!store.claim(operationId,owner)) {
            if(store.finished(operationId))return operationId;
            throw new RetryLaterException("Webhook management is active on another worker",60);
        }
        try {
            var op=store.operation(operationId);
            var initial=store.workerIntegration(operationId,owner);
            if(!Objects.equals(op.workspace,initial.getWorkspace())||!Objects.equals(op.callbackHash,callbackHash(initial.getApiLabel())))
                throw new IllegalStateException("Integration configuration changed; start a new operation");
            if(op.action.equals("ROTATE"))store.beginRotation(operationId,owner);
            int processed=0;
            while(true) {
                var tasks=store.pending(operationId);if(tasks.isEmpty())break;
                for(var task:tasks) {
                    progress.accept("Checking "+(task.scope.isEmpty()?"workspace":task.scope));
                    var bb=store.workerIntegration(operationId,owner);var api=(BBCloudApi)bb.createApi();
                    String slug=task.scope.isEmpty()?null:task.scope;
                    try {
                        if(!Objects.equals(op.workspace,bb.getWorkspace())||!Objects.equals(op.callbackHash,callbackHash(bb.getApiLabel()))) {
                            store.failure(operationId,owner,task.id,"CONFIGURATION_CHANGED",false);continue;
                        }
                        String outcome="CHECKED",hookId=task.hookUuid;
                        if(op.action.equals("DELETE")) {api.deleteHook(slug,publicUrl,task.hookUuid);outcome="DELETED";}
                        else if(op.action.equals("UPSERT")) {
                            // Recheck selection at execution time; disable cannot race into a new hook unnoticed.
                            if(slug!=null){var repo=repositories.findByApiLabelAndRepoName(bb.getApiLabel(),slug);
                                if(repo==null||!repo.isEnabled())throw new IllegalArgumentException("Repository is disabled or absent");}
                            var mutation=api.upsertHook(slug,publicUrl,BBWebhookPreset.valueOf(op.preset).events(),op.active,task.hookUuid,false);
                            outcome=mutation.outcome();hookId=mutation.uuid();
                        } else if(op.action.equals("ROTATE")) {
                            var live=slug==null?api.listWorkspaceHooks(publicUrl):api.listRepoHooks(slug,publicUrl);
                            for(var hook:live)if(hook.owned()) {
                                progress.accept("Rotating "+(slug==null?"workspace":slug));
                                store.assertOwner(operationId,owner);
                                api.upsertHook(slug,publicUrl,hook.events(),hook.active(),hook.uuid(),true);
                                LOG.info("webhook user={} label={} repo={} hook={} action=ROTATE result=UPDATED",clean(op.actor),bb.getApiLabel(),task.scope,hook.uuid());
                            }
                            outcome="ROTATED";
                        }
                        store.assertOwner(operationId,owner);
                        var live=slug==null?api.listWorkspaceHooks(publicUrl):api.listRepoHooks(slug,publicUrl);
                        store.snapshot(operationId,owner,task.id,live,callbackHash(bb.getApiLabel()),outcome);
                        LOG.info("webhook user={} label={} repo={} hook={} action={} result={}",clean(op.actor),bb.getApiLabel(),task.scope,hookId,op.action,outcome);
                    } catch(BBWebhookException e) {
                        store.failure(operationId,owner,task.id,e.getCode(),e.getStatus()==429);
                        if(e.getStatus()==429)throw new RetryLaterException("Bitbucket webhook rate limit",Math.max(1,e.getRetryAfterSeconds()));
                        LOG.info("webhook user={} label={} repo={} action={} result={}",clean(op.actor),bb.getApiLabel(),task.scope,op.action,e.getCode());
                    } catch(IllegalArgumentException e) {store.failure(operationId,owner,task.id,"SELECTION_OR_OWNERSHIP_CHANGED",false);}
                    catch(RuntimeException e) {store.failure(operationId,owner,task.id,"ERROR",false);}
                    // Yield through the existing durable queue, rather than blocking a worker to throttle a large workspace.
                    if(++processed>=10&&!store.pending(operationId).isEmpty())throw new RetryLaterException("Webhook batch checkpoint",5);
                }
            }
            store.finish(operationId,owner);return operationId;
        } catch(RetryLaterException e){throw e;}
        catch(RuntimeException e){store.abort(operationId,owner);throw new IllegalStateException("Webhook operation interrupted; retry the failed scopes");}
        finally {store.release(operationId,owner);}
    }
    private static String clean(String value){return value==null?"system":value.replaceAll("\\p{Cntrl}"," ");}
}
