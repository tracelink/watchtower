package com.tracelink.appsec.watchtower.core.scan.apiintegration;

import java.security.Principal;
import java.util.*;
import org.springframework.http.*;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import com.tracelink.appsec.watchtower.core.auth.model.CorePrivilege;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.webhook.*;

/** Cached reads and durable commands. Workspace settings are independent of repository hooks. */
@RestController
@RequestMapping("/apisettings/{label}/webhooks")
@PreAuthorize("hasAuthority('"+CorePrivilege.API_SETTINGS_VIEW_NAME+"')")
public class BitbucketWebhookController {
    private final BBWebhookManagementService service;
    public BitbucketWebhookController(BBWebhookManagementService service){this.service=service;}
    public record Settings(BBWebhookPreset preset,boolean active,String uuid) { }
    public record Selection(List<String> repositories,BBWebhookPreset preset,boolean active) { }
    public record Refresh(String repository,Boolean workspaceOnly) { }
    public record Rotation(String confirmLabel) { }
    @GetMapping public Object list(@PathVariable String label,@RequestParam(defaultValue="")String q,@RequestParam(defaultValue="0")int page){return service.inventory(label,q,page);}
    @GetMapping("/repositories") public Object picker(@PathVariable String label,@RequestParam(defaultValue="")String q,@RequestParam(defaultValue="0")int page){return service.picker(label,q,page);}
    @GetMapping("/workspace/live") public Object liveWorkspace(@PathVariable String label){return service.live(label,null);}
    @GetMapping("/repos/{slug}/live") public Object liveRepo(@PathVariable String label,@PathVariable String slug){return service.live(label,slug);}
    @PostMapping("/refresh") public Object refresh(@PathVariable String label,@RequestBody(required=false)Refresh request,Principal user){
        return accepted(service.refresh(label,request==null?null:request.repository(),request!=null&&Boolean.TRUE.equals(request.workspaceOnly()),user.getName()));
    }
    @PutMapping("/workspace")
    @PreAuthorize("hasAuthority('"+CorePrivilege.API_SETTINGS_MODIFY_NAME+"')")
    public Object workspace(@PathVariable String label,@RequestBody Settings settings,Principal user){return accepted(service.enqueue(label,"UPSERT",settings.preset(),settings.active(),null,settings.uuid(),user.getName()));}
    @DeleteMapping("/workspace")
    @PreAuthorize("hasAuthority('"+CorePrivilege.API_SETTINGS_MODIFY_NAME+"')")
    public Object deleteWorkspace(@PathVariable String label,@RequestParam String uuid,Principal user){return accepted(service.enqueue(label,"DELETE",BBWebhookPreset.ALL,true,null,uuid,user.getName()));}
    @PostMapping("/repos")
    @PreAuthorize("hasAuthority('"+CorePrivilege.API_SETTINGS_MODIFY_NAME+"')")
    public Object repos(@PathVariable String label,@RequestBody Selection selection,Principal user){
        if(selection.repositories()==null)throw new IllegalArgumentException("Choose repositories");
        return accepted(service.enqueue(label,"UPSERT",selection.preset(),selection.active(),selection.repositories(),null,user.getName()));
    }
    @PatchMapping("/repos/{slug}/{uuid}")
    @PreAuthorize("hasAuthority('"+CorePrivilege.API_SETTINGS_MODIFY_NAME+"')")
    public Object updateRepo(@PathVariable String label,@PathVariable String slug,@PathVariable String uuid,@RequestBody Settings settings,Principal user){return accepted(service.enqueue(label,"UPSERT",settings.preset(),settings.active(),List.of(slug),uuid,user.getName()));}
    @DeleteMapping("/repos/{slug}/{uuid}")
    @PreAuthorize("hasAuthority('"+CorePrivilege.API_SETTINGS_MODIFY_NAME+"')")
    public Object deleteRepo(@PathVariable String label,@PathVariable String slug,@PathVariable String uuid,Principal user){return accepted(service.enqueue(label,"DELETE",BBWebhookPreset.ALL,true,List.of(slug),uuid,user.getName()));}
    @PostMapping("/rotate-secret")
    @PreAuthorize("hasAuthority('"+CorePrivilege.API_SETTINGS_MODIFY_NAME+"')")
    public Object rotate(@PathVariable String label,@RequestBody Rotation request,Principal user){
        if(!label.equals(request.confirmLabel()))throw new IllegalArgumentException("Type the integration label to rotate its signing secret");
        return accepted(service.enqueue(label,"ROTATE",BBWebhookPreset.ALL,true,List.of(),null,user.getName()));
    }
    @GetMapping("/jobs/{id}") public Object job(@PathVariable String label,@PathVariable String id,@RequestParam(defaultValue="0")int page){return service.operation(label,id,page);}
    @PostMapping("/jobs/{id}/retry")
    @PreAuthorize("hasAuthority('"+CorePrivilege.API_SETTINGS_MODIFY_NAME+"')")
    public Object retry(@PathVariable String label,@PathVariable String id,Principal user){service.retry(label,id,user.getName());return accepted(id);}
    private ResponseEntity<?> accepted(String id){return ResponseEntity.accepted().header(HttpHeaders.CACHE_CONTROL,"no-store").body(Map.of("operationId",id));}
    @ExceptionHandler(com.tracelink.appsec.watchtower.core.scan.code.scm.api.bb.BBWebhookException.class)
    ResponseEntity<?> providerFailure(com.tracelink.appsec.watchtower.core.scan.code.scm.api.bb.BBWebhookException e){
        var response=ResponseEntity.status(e.getStatus()==429?503:502);
        if(e.getStatus()==429)response.header("Retry-After",String.valueOf(e.getRetryAfterSeconds()));
        return response.body(Map.of("code",e.getCode(),"upstreamStatus",e.getStatus()));
    }
    @ExceptionHandler(IllegalArgumentException.class) ResponseEntity<?> badInput(IllegalArgumentException e){return ResponseEntity.badRequest().body(Map.of("code","INVALID_REQUEST","message",e.getMessage()));}
    @ExceptionHandler(IllegalStateException.class) ResponseEntity<?> conflict(IllegalStateException e){return ResponseEntity.status(409).body(Map.of("code","CONFLICT","message",e.getMessage()));}
    @ModelAttribute public void noCache(jakarta.servlet.http.HttpServletResponse response){response.setHeader("Cache-Control","no-store");}
}
