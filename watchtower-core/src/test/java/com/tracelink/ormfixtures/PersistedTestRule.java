package com.tracelink.ormfixtures;

import jakarta.persistence.*;
import com.tracelink.appsec.watchtower.core.rule.*;

/** Outside application entity scanning; explicitly registered by the ledger fixture only. */
@Entity @Table(name="persisted_test_rules")
public class PersistedTestRule extends RuleEntity {
 @Override public RuleDto toDto(){return new com.tracelink.appsec.watchtower.core.mock.MockRuleEntity().toDto();}
}
