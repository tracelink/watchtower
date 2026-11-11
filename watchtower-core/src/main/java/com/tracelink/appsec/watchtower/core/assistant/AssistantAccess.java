package com.tracelink.appsec.watchtower.core.assistant;

import java.util.*;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.security.access.AccessDeniedException;
import com.tracelink.appsec.watchtower.core.auth.repository.UserRepository;

/** Reload local account/role grants for each invocation, replay and endpoint. */
@Service
public class AssistantAccess {
 private final UserRepository users;
 public AssistantAccess(UserRepository users){this.users=users;}
 @Transactional(readOnly=true)
 public Set<String> authorities(String owner){var u=users.findByUsername(owner);if(u==null||u.getEnabled()==0)throw new AccessDeniedException("Account unavailable");Set<String> grants=new HashSet<>();u.getRoles().forEach(r->r.getPrivileges().forEach(p->grants.add(p.getName())));return grants;}
 @Transactional(readOnly=true)
 public void require(String owner,String authority){if(!authorities(owner).contains(authority))throw new AccessDeniedException("Access revoked or unavailable");}
}
