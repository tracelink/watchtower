package com.tracelink.appsec.watchtower.core.scan.code.scm.pr.bypass;
import java.util.*;
import org.springframework.stereotype.Service;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.dao.DataIntegrityViolationException;
import com.tracelink.appsec.watchtower.core.persistence.LedgerRepository;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.webhook.BBWebhookStore;
@Service
public class PRCommentDeliveryClaims {
 private final LedgerRepository records; private final TransactionTemplate transaction;
 public record Claim(String id,String owner) { }
 public PRCommentDeliveryClaims(LedgerRepository records,PlatformTransactionManager manager){this.records=records;this.transaction=new TransactionTemplate(manager);}
 public Claim claim(String label,String repo,String prId,long commentId){
  String id=BBWebhookStore.hash(String.join("\u0000",label,repo,prId,String.valueOf(commentId)));
  try{return transaction.execute(tx->{long now=System.currentTimeMillis();var receipt=records.lock(PRCommentReceiptEntity.class,id);
   if(receipt!=null&&receipt.expiresAt>now)return null;
   boolean isNew=receipt==null;
   if(isNew){receipt=new PRCommentReceiptEntity();receipt.id=id;}
   // The owner is set before the insert: the column is NOT NULL and the row is written as soon as it is persisted.
   receipt.owner=UUID.randomUUID().toString();receipt.expiresAt=now+86400000L;
   if(isNew)records.insert(receipt);
   records.flush();return new Claim(id,receipt.owner);
  });}catch(DataIntegrityViolationException e){return null;}
 }
 public void release(Claim claim){if(claim!=null)records.update("DELETE FROM PRCommentReceiptEntity r WHERE r.id=?1 AND r.owner=?2",claim.id(),claim.owner());}
 @Scheduled(fixedDelayString="${watchtower.webhooks.receipt-cleanup-ms:3600000}")
 public void cleanup(){long now=System.currentTimeMillis();var ids=records.list(String.class,"SELECT r.id FROM PRCommentReceiptEntity r WHERE r.expiresAt<?1 ORDER BY r.expiresAt",0,1000,now);if(!ids.isEmpty())records.update("DELETE FROM PRCommentReceiptEntity r WHERE r.id IN ?1 AND r.expiresAt<?2",ids,now);}
}
