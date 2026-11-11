package com.tracelink.appsec.watchtower.core.persistence;

import java.util.*;
import jakarta.persistence.*;
import jakarta.persistence.criteria.CriteriaBuilder;
import jakarta.persistence.criteria.CriteriaQuery;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

/** Hibernate repository for the application ledgers. Queries use entity attributes and bound parameters. */
@Repository
@Transactional(readOnly=true)
public class LedgerRepository {
 @PersistenceContext private EntityManager entities;
 public LedgerRepository() { }
 public LedgerRepository(EntityManager entities) { this.entities=entities; }
 public <T> T find(Class<T> type,Object id) { return entities.find(type,id); }
 @Transactional public <T> T lock(Class<T> type,Object id) { return entities.find(type,id,LockModeType.PESSIMISTIC_WRITE); }
 @Transactional public void lockScope(String scope) {
  if(lock(ApplicationPersistenceLockEntity.class,scope)==null)throw new IllegalStateException("Application persistence lock missing; apply migrations");
 }
 @Transactional public <T> T insert(T entity) { entities.persist(entity); return entity; }
 @Transactional public <T> T save(T entity) { return entities.merge(entity); }
 @Transactional public void flush() { entities.flush(); }
 public <T> List<T> listBeforeFlush(Class<T> type,String jpql,Object... parameters) {
  var query=entities.createQuery(jpql,type).setFlushMode(FlushModeType.COMMIT);bind(query,parameters);return query.setMaxResults(1).getResultList();
 }
 @Transactional public void remove(Object entity) { entities.remove(entities.contains(entity)?entity:entities.merge(entity)); }
 public <T> List<T> list(Class<T> type,String jpql,int offset,int limit,Object... parameters) {
  var query=entities.createQuery(jpql,type);bind(query,parameters);
  return query.setFirstResult(offset).setMaxResults(limit).getResultList();
 }
 /** The JPA Criteria builder: queries built from it have no query text to assemble, so there is nothing to inject into. */
 public CriteriaBuilder criteria() { return entities.getCriteriaBuilder(); }
 /** As {@link #maps(String,int,int,Object...)}, for a query built with {@link #criteria()}; every selection needs an alias. */
 public List<Map<String,Object>> maps(CriteriaQuery<Tuple> query,int offset,int limit) {
  return rows(entities.createQuery(query).setFirstResult(offset).setMaxResults(limit).getResultList());
 }
 public <T> T scalar(CriteriaQuery<T> query) { return entities.createQuery(query).getSingleResult(); }
 public List<Map<String,Object>> maps(String jpql,int offset,int limit,Object... parameters) {
  var query=entities.createQuery(jpql,Tuple.class);bind(query,parameters);
  return rows(query.setFirstResult(offset).setMaxResults(limit).getResultList());
 }
 private static List<Map<String,Object>> rows(List<Tuple> tuples) {
  List<Map<String,Object>> rows=new ArrayList<>();
  for(var tuple:tuples) {
   if(tuple.getElements().size()==1 && tuple.get(0) instanceof LedgerRecord record) { rows.add(record.values()); continue; }
   Map<String,Object> row=new LinkedHashMap<>();
   for(var element:tuple.getElements()) {
    if(element.getAlias()==null)throw new IllegalArgumentException("Ledger projections require explicit aliases");
    row.put(element.getAlias(),tuple.get(element));
   }
   rows.add(row);
  }
  return rows;
 }
 public <T> T scalar(Class<T> type,String jpql,Object... parameters) {
  var query=entities.createQuery(jpql,type);bind(query,parameters);return query.getSingleResult();
 }
 @Transactional public int update(String jpql,Object... parameters) {
  entities.flush();var query=entities.createQuery(jpql);bind(query,parameters);
  int changed=query.executeUpdate();entities.clear();return changed;
 }
 private static void bind(Query query,Object[] parameters) {
  for(int i=0;i<parameters.length;i++)query.setParameter(i+1,parameters[i]);
 }
}
