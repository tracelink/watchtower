package com.tracelink.appsec.watchtower.core.rule.candidate;

import org.springframework.stereotype.Component;
import com.tracelink.appsec.watchtower.core.rule.RuleEntity;

/** Hibernate obtains this listener from Spring's BeanContainer; history participates in the write. */
@Component
public class RuleDefinitionListener {
 private final RuleDefinitionHistory history;
 public RuleDefinitionListener(@org.springframework.context.annotation.Lazy RuleDefinitionHistory history) { this.history=history; }
 @jakarta.persistence.PostLoad
 public void loaded(RuleEntity entity) { history.watch(); }
 @jakarta.persistence.PostPersist
 @jakarta.persistence.PostUpdate
 public void saved(RuleEntity entity) { history.observe(entity.toDto()); }
}
