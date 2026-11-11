package com.tracelink.appsec.watchtower.core.assistant.context;

import java.util.*;
import org.springframework.stereotype.Component;
import com.tracelink.appsec.watchtower.core.scan.repository.RepositoryRepository;

/** The card for a repository page: what it is and which ruleset applies, no paths or findings. */
@Component
public class RepositoryContextProvider implements ContextProvider {
 private final RepositoryRepository repositories;
 public RepositoryContextProvider(RepositoryRepository repositories){this.repositories=repositories;}
 @Override public String kind(){return "repository";}
 @Override public Set<String> grants(){return Set.of("Repository Settings View");}
 @Override public ContextCard resolve(ContextRequest.Ids ids){
  if(ids.repoId()==null||ids.repoId()<1)return ContextCard.unavailable(kind());
  var repo=repositories.findById(ids.repoId()).orElse(null);
  if(repo==null)return ContextCard.unavailable(kind());
  var facts=new LinkedHashMap<String,Object>();
  facts.put("name",repo.getRepoName());facts.put("integration",repo.getApiLabel());
  if(repo.getPrimaryLanguage()!=null)facts.put("language",repo.getPrimaryLanguage());
  if(repo.getRuleset()!=null){facts.put("ruleset",repo.getRuleset().getName());facts.put("ruleset_id",repo.getRuleset().getId());}
  facts.put("scanning_paused",repo.isScanningPaused());
  if(repo.getLastRepoScanId()!=null)facts.put("last_repository_scan",repo.getLastRepoScanId());
  return ContextCard.ok(kind(),"Repository · "+repo.getRepoName(),facts,ContextService.idMap(new ContextRequest.Ids(null,null,null,repo.getId(),null)));
 }
}
