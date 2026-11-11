package com.tracelink.appsec.module.awssecurity;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.security.access.AccessDeniedException;
import com.tracelink.appsec.watchtower.core.auth.repository.UserRepository;

/** Setup execution reloads account grants independently of Assistant or Chat settings. */
@Service
public class AwsSecuritySetupAccess {
 private final UserRepository users;
 public AwsSecuritySetupAccess(UserRepository users){this.users=users;}
 @Transactional(readOnly=true)
 public boolean allowed(String name){
  var user=users.findByUsername(name);if(user==null||user.getEnabled()==0)return false;
  var grants=new java.util.HashSet<String>();
  user.getRoles().forEach(r->r.getPrivileges().forEach(p->grants.add(p.getName())));
  return grants.containsAll(java.util.Set.of("AWS Security Administration","Repository Settings View"));
 }
 @Transactional(readOnly=true)
 public void require(String name){if(!allowed(name))throw new AccessDeniedException("AWS setup access is unavailable or revoked");}
}
