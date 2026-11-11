package com.tracelink.appsec.module.awssecurity;

import java.util.*;
import java.util.concurrent.*;
import org.junit.jupiter.api.*;
import static org.junit.jupiter.api.Assertions.*;
import org.h2.jdbcx.JdbcDataSource;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.init.ResourceDatabasePopulator;
import org.springframework.core.io.ClassPathResource;
import org.springframework.orm.jpa.*;
import org.springframework.orm.jpa.vendor.HibernateJpaVendorAdapter;
import org.springframework.aop.framework.ProxyFactory;
import org.springframework.transaction.annotation.AnnotationTransactionAttributeSource;
import org.springframework.transaction.interceptor.TransactionInterceptor;
import com.tracelink.appsec.watchtower.core.scan.code.CodeScanType;

/** Real migration + Hibernate transactions; concurrency assertions do not mock JPA. */
class AwsSecurityPersistenceTest {
    jakarta.persistence.EntityManagerFactory factory;
    AwsSecurityRunRepository runs; AwsSecurityPermitRepository permits; AwsSecurityPersistence persistence;
    JdbcTemplate jdbc;
    @BeforeEach void setup() {
        var ds=new JdbcDataSource(); ds.setURL("jdbc:h2:mem:"+UUID.randomUUID()+";MODE=MySQL;DATABASE_TO_LOWER=TRUE;DB_CLOSE_DELAY=-1;LOCK_TIMEOUT=10000");
        jdbc=new JdbcTemplate(ds); jdbc.execute("CREATE TABLE rules(rule_id BIGINT PRIMARY KEY)");
        new ResourceDatabasePopulator(new ClassPathResource("db/awssecurity/V001__AWS_Security_Agent.sql"),
                new ClassPathResource("db/awssecurity/V002__Aws_Evidence_Qualification_And_Metrics.sql"),
                new ClassPathResource("db/awssecurity/V003__Synthetic_Setup_Tests.sql"),
                new ClassPathResource("db/awssecurity/V004__Concurrent_Review_Permits.sql"),
                new ClassPathResource("db/awssecurity/V005__AWS_Review_Capacity_Setting.sql"),
                new ClassPathResource("db/awssecurity/V006__AWS_Source_Evidence_Policy.sql"),
                new ClassPathResource("db/awssecurity/V007__Shared_Repository_Review.sql"),
            new ClassPathResource("db/awssecurity/V008__AWS_Failure_Policy.sql")).execute(ds);
        var builder=new LocalContainerEntityManagerFactoryBean();builder.setDataSource(ds);builder.setJpaVendorAdapter(new HibernateJpaVendorAdapter());
        builder.setPackagesToScan("com.tracelink.appsec.module.awssecurity");
        builder.setPersistenceUnitPostProcessors(unit->unit.getManagedClassNames().removeIf(n->n.equals(AwsSecurityRuleEntity.class.getName())));
        builder.setJpaPropertyMap(Map.of("hibernate.hbm2ddl.auto","validate"));builder.afterPropertiesSet();factory=builder.getObject();
        var tx=new JpaTransactionManager(factory); var em=SharedEntityManagerCreator.createSharedEntityManager(factory);
        var repositoryFactory=new org.springframework.data.jpa.repository.support.JpaRepositoryFactory(em);
        runs=repositoryFactory.getRepository(AwsSecurityRunRepository.class); permits=repositoryFactory.getRepository(AwsSecurityPermitRepository.class);
        var proxy=new ProxyFactory(new AwsSecurityPersistence(runs,permits));proxy.setProxyTargetClass(true);
        proxy.addAdvice(new TransactionInterceptor(tx,new AnnotationTransactionAttributeSource()));persistence=(AwsSecurityPersistence)proxy.getProxy();
    }
    @AfterEach void close(){if(factory!=null)factory.close();jdbc.execute("DROP ALL OBJECTS");}
    @Test void duplicateEnlistmentKeepsParentAndOutboxAtomic() {
        var snapshot=AwsTestSupport.snapshot("one",CodeScanType.PULL_REQUEST);var parentCalls=new java.util.concurrent.atomic.AtomicInteger();
        var first=persistence.enlist(snapshot,14400,null,()->{parentCalls.incrementAndGet();return 77;});
        var second=persistence.enlist(snapshot,14400,null,()->{parentCalls.incrementAndGet();return 88;});
        assertEquals(first.id,second.id);assertEquals(77,second.parentId);assertEquals(1,parentCalls.get());assertTrue(second.dispatchPending);
        assertEquals(77,AwsSecuritySnapshot.decode(second.snapshotJson).context().scanId());
        assertEquals(1,runs.operationalTotals().getFirst().getJobs());assertEquals(0,runs.countByNeedsReconciliationTrue());
        assertTrue(runs.oldestInput().isEmpty());assertTrue(runs.averageLatencyMillis().isEmpty());
    }
    @Test void concurrentPodsCannotBothAcquireTheRemoteSlot() throws Exception {
        var first=persistence.enlist(AwsTestSupport.snapshot("one",CodeScanType.PULL_REQUEST),14400,null);
        var second=persistence.enlist(AwsTestSupport.snapshot("two",CodeScanType.PULL_REQUEST),14400,null);
        try(var pool=Executors.newFixedThreadPool(2)) {
            var start=new CountDownLatch(1);
            var a=pool.submit(()->{start.await();return persistence.claim(first.id,"pod-a",System.currentTimeMillis()).isPresent();});
            var b=pool.submit(()->{start.await();return persistence.claim(second.id,"pod-b",System.currentTimeMillis()).isPresent();});start.countDown();
            assertNotEquals(a.get(10,TimeUnit.SECONDS),b.get(10,TimeUnit.SECONDS));
        }
    }
    @Test void twoRemoteSlotsAdmitTwoPodsButQueueTheThird() throws Exception {
        var raw = new AwsSecurityPersistence(runs, permits, new AwsSecurityCapacity(2));
        var proxy = new ProxyFactory(raw); proxy.setProxyTargetClass(true);
        proxy.addAdvice(new TransactionInterceptor(new JpaTransactionManager(factory), new AnnotationTransactionAttributeSource()));
        var concurrent = (AwsSecurityPersistence) proxy.getProxy();
        var ids = java.util.stream.Stream.of("one", "two", "three")
            .map(name -> concurrent.enlist(AwsTestSupport.snapshot(name, CodeScanType.PULL_REQUEST), 14400, null).id).toList();
        try (var pool = Executors.newFixedThreadPool(3)) {
            var start = new CountDownLatch(1);
            var claims = ids.stream().map(id -> pool.submit(() -> {
                start.await(); return concurrent.claim(id, UUID.randomUUID().toString(), System.currentTimeMillis()).isPresent();
            })).toList();
            start.countDown();
            assertEquals(2, claims.stream().filter(f -> {
                try { return f.get(10, TimeUnit.SECONDS); } catch (Exception e) { throw new AssertionError(e); }
            }).count());
            assertEquals(2, runs.activePermitCount());
        }
    }
    @Test void lostLeaseCannotPublishAndUnknownMutationRetainsAdmissionGuard() {
        var first=persistence.enlist(AwsTestSupport.snapshot("one",CodeScanType.PULL_REQUEST),14400,null);
        var old=persistence.claim(first.id,"old",System.currentTimeMillis()).orElseThrow();
        persistence.update(first.id,"old",old.fence,r->r.stage=AwsSecurityRun.Stage.CREATING);
        jdbc.update("UPDATE aws_security_scan_runs SET lease_until=0 WHERE id=?",first.id);
        var replacement=persistence.claim(first.id,"new",System.currentTimeMillis()).orElseThrow();
        assertThrows(AwsSecurityPersistence.LostOwnership.class,()->persistence.update(first.id,"old",old.fence,r->r.artifactKey="stale"));
        persistence.release(first.id,"new",replacement.fence);
        var second=persistence.enlist(AwsTestSupport.snapshot("two",CodeScanType.PULL_REQUEST),14400,null);
        assertTrue(persistence.claim(second.id,"other",System.currentTimeMillis()).isEmpty());assertEquals(first.id,permits.findById(1).orElseThrow().runId);
    }
    @Test void terminalProofReleasesPermitButLocalTimeoutDoesNot() {
        var first=persistence.enlist(AwsTestSupport.snapshot("one",CodeScanType.REPOSITORY),14400,null);
        var owned=persistence.claim(first.id,"owner",System.currentTimeMillis()).orElseThrow();
        persistence.update(first.id,"owner",owned.fence,r->{r.stage=AwsSecurityRun.Stage.FAILED;r.jobId="remote";});
        persistence.release(first.id,"owner",owned.fence);assertEquals(first.id,permits.findById(1).orElseThrow().runId);
        owned=persistence.claim(first.id,"owner",System.currentTimeMillis()).orElseThrow();
        persistence.update(first.id,"owner",owned.fence,r->r.providerTerminal=true);
        persistence.release(first.id,"owner",owned.fence);assertNull(permits.findById(1).orElseThrow().runId);
    }
    @Test void queuedPrHasPriorityOverNewRepositoryWork() {
        var repo=persistence.enlist(AwsTestSupport.snapshot("repo",CodeScanType.REPOSITORY),14400,null);
        persistence.enlist(AwsTestSupport.snapshot("pr",CodeScanType.PULL_REQUEST),14400,null);
        assertTrue(persistence.claim(repo.id,"repo-worker",System.currentTimeMillis()).isEmpty());
    }
}
