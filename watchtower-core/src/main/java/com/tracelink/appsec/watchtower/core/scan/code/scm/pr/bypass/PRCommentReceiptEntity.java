package com.tracelink.appsec.watchtower.core.scan.code.scm.pr.bypass;
import jakarta.persistence.*;
/** A bounded-lived delivery reservation shared by pods; no comment text or author data. */
@Entity
@Table(name="pr_comment_receipts")
public class PRCommentReceiptEntity {
 @Id @Column(name="receipt_id") String id;
 @Column(name="owner_token",nullable=false) String owner;
 @Column(name="expires_at") long expiresAt;
}
