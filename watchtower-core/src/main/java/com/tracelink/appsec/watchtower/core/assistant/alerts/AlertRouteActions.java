package com.tracelink.appsec.watchtower.core.assistant.alerts;

import java.util.List;
import com.tracelink.appsec.watchtower.core.alerting.AlertAggregation;
import com.tracelink.appsec.watchtower.core.rule.RulePriority;

/**
 * The only alert changes that can be drafted: add a route, change one, or remove one. Channels (and their
 * webhook URLs) are never part of a change set, and nothing here sends or applies anything.
 */
public final class AlertRouteActions {
 private AlertRouteActions() { }
 public enum Type { ADD, UPDATE, REMOVE }
 /**
  * ADD and UPDATE carry the whole route; UPDATE and REMOVE name an existing route by id and the version of it
  * the draft was made against ({@code baseVersion}), so a route edited since is refused rather than overwritten.
  */
 public record Operation(Type type,Long routeId,String alertType,Long channelId,RulePriority minPriority,String apiLabelFilter,
   String repoInclude,String repoExclude,AlertAggregation aggregation,Integer dedupeWindowHours,Long baseVersion) { }
 public record Request(String idempotencyKey,List<Operation> operations) { }
 public record Approval(long version,String contentHash) { }
 /** A route as it is or would be, with the channel's name (never its URL) and the version it was read at. */
 public record RouteState(Long routeId,long version,String alertType,long channelId,String channelName,boolean channelEnabled,boolean enabled,RulePriority minPriority,
   String apiLabelFilter,String repoInclude,String repoExclude,AlertAggregation aggregation,int dedupeWindowHours) { }
 public record Change(Type type,RouteState before,RouteState after) { }
 public record Preview(List<Change> changes) { }
 public record View(String id,long version,String status,String contentHash,long expiresAt,Preview preview,Object receipt) { }
}
