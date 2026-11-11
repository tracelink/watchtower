package com.tracelink.appsec.module.awssecurity;

import static org.junit.jupiter.api.Assertions.*;

import java.util.*;
import java.util.concurrent.*;
import org.h2.jdbcx.JdbcDataSource;
import org.junit.jupiter.api.*;
import org.springframework.core.io.ClassPathResource;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.init.ResourceDatabasePopulator;
import org.springframework.orm.jpa.*;
import org.springframework.orm.jpa.vendor.HibernateJpaVendorAdapter;

/** The per-repository review and its lock, against the real migration and Hibernate (no mocked JPA). */
class AwsSecurityRepoReviewsTest {
    jakarta.persistence.EntityManagerFactory factory;
    AwsSecurityRepoReviews reviews;
    JdbcTemplate jdbc;
    static final String SPACE = "as-space";
    static final String TITLE = "watchtower-bb-repo-r2";

    @BeforeEach void setup() {
        var ds = new JdbcDataSource();
        ds.setURL("jdbc:h2:mem:" + UUID.randomUUID() + ";MODE=MySQL;DATABASE_TO_LOWER=TRUE;DB_CLOSE_DELAY=-1;LOCK_TIMEOUT=10000");
        jdbc = new JdbcTemplate(ds);
        jdbc.execute("CREATE TABLE rules(rule_id BIGINT PRIMARY KEY)");
        new ResourceDatabasePopulator(new ClassPathResource("db/awssecurity/V001__AWS_Security_Agent.sql"),
            new ClassPathResource("db/awssecurity/V002__Aws_Evidence_Qualification_And_Metrics.sql"),
            new ClassPathResource("db/awssecurity/V003__Synthetic_Setup_Tests.sql"),
            new ClassPathResource("db/awssecurity/V004__Concurrent_Review_Permits.sql"),
            new ClassPathResource("db/awssecurity/V005__AWS_Review_Capacity_Setting.sql"),
            new ClassPathResource("db/awssecurity/V006__AWS_Source_Evidence_Policy.sql"),
            new ClassPathResource("db/awssecurity/V007__Shared_Repository_Review.sql"),
            new ClassPathResource("db/awssecurity/V008__AWS_Failure_Policy.sql")).execute(ds);
        var builder = new LocalContainerEntityManagerFactoryBean();
        builder.setDataSource(ds); builder.setJpaVendorAdapter(new HibernateJpaVendorAdapter());
        builder.setPackagesToScan("com.tracelink.appsec.module.awssecurity");
        builder.setPersistenceUnitPostProcessors(unit -> unit.getManagedClassNames().removeIf(n -> n.equals(AwsSecurityRuleEntity.class.getName())));
        builder.setJpaPropertyMap(Map.of("hibernate.hbm2ddl.auto", "validate")); builder.afterPropertiesSet(); factory = builder.getObject();
        var tx = new JpaTransactionManager(factory);
        var em = SharedEntityManagerCreator.createSharedEntityManager(factory);
        var repository = new org.springframework.data.jpa.repository.support.JpaRepositoryFactory(em).getRepository(AwsSecurityRepoReviewRepository.class);
        reviews = new AwsSecurityRepoReviews(repository, tx);
    }
    @AfterEach void close() { if (factory != null) factory.close(); jdbc.execute("DROP ALL OBJECTS"); }

    @Test void theFirstScanTakesTheLockAndAnotherWaitsUntilItIsReleased() {
        var first = reviews.acquire(2, SPACE, TITLE, "run-1", 1000);
        assertTrue(first.held());assertNull(first.reviewId());
        assertFalse(reviews.acquire(2, SPACE, TITLE, "run-2", 2000).held(), "the lock is taken");
        assertTrue(reviews.acquire(2, SPACE, TITLE, "run-1", 3000).held(), "the holder can ask again");
        reviews.release(2, "run-1");
        assertTrue(reviews.acquire(2, SPACE, TITLE, "run-2", 4000).held());
    }
    @Test void aDifferentRepositoryNeverWaits() {
        assertTrue(reviews.acquire(2, SPACE, TITLE, "run-1", 1000).held());
        assertTrue(reviews.acquire(3, SPACE, "watchtower-bb-other-r3", "run-2", 1000).held());
    }
    @Test void anExpiredLockCanBeTakenOverAndTheOldHolderLosesIt() {
        reviews.acquire(2, SPACE, TITLE, "run-1", 1000);
        long after = 1000 + AwsSecurityRepoReviews.LEASE_MS + 1;
        assertTrue(reviews.acquire(2, SPACE, TITLE, "run-2", after).held());
        assertFalse(reviews.holds(2, "run-1", after), "the old holder must stop before touching the review");
        assertTrue(reviews.holds(2, "run-2", after));
        reviews.recordReview(2, "run-1", "cr-stolen");
        assertNull(reviews.acquire(2, SPACE, TITLE, "run-2", after).reviewId(), "a run that lost the lock cannot record");
    }
    @Test void holdingExtendsTheLeaseSoALongStartIsNotTakenOver() {
        reviews.acquire(2, SPACE, TITLE, "run-1", 1000);
        long nearEnd = 1000 + AwsSecurityRepoReviews.LEASE_MS - 10;
        assertTrue(reviews.holds(2, "run-1", nearEnd));
        assertFalse(reviews.acquire(2, SPACE, TITLE, "run-2", nearEnd + 20).held(), "the extended lease is still live");
    }
    @Test void theReviewIsRememberedForTheNextScanAndCanBeForgottenWhenAwsLostIt() {
        reviews.acquire(2, SPACE, TITLE, "run-1", 1000);
        reviews.recordReview(2, "run-1", "cr-1");reviews.release(2, "run-1");
        var next = reviews.acquire(2, SPACE, TITLE, "run-2", 2000);
        assertTrue(next.held());assertEquals("cr-1", next.reviewId());
        reviews.forgetReview(2, "run-2");
        assertNull(reviews.acquire(2, SPACE, TITLE, "run-2", 3000).reviewId());
    }
    @Test void anotherAgentSpaceDoesNotReuseTheOldReview() {
        reviews.acquire(2, SPACE, TITLE, "run-1", 1000);reviews.recordReview(2, "run-1", "cr-1");reviews.release(2, "run-1");
        var moved = reviews.acquire(2, "as-other-space", TITLE, "run-2", 2000);
        assertTrue(moved.held());assertNull(moved.reviewId());
    }
    @Test void twoScansStartingAtTheSameTimeCannotBothHoldTheFirstLock() throws Exception {
        var pool = Executors.newFixedThreadPool(2);
        try {
            var start = new CountDownLatch(1);
            Callable<Boolean> a = () -> { start.await(); return reviews.acquire(9, SPACE, TITLE, "run-a", 1000).held(); };
            Callable<Boolean> b = () -> { start.await(); return reviews.acquire(9, SPACE, TITLE, "run-b", 1000).held(); };
            var fa = pool.submit(a); var fb = pool.submit(b); start.countDown();
            assertEquals(1, (fa.get(20, TimeUnit.SECONDS) ? 1 : 0) + (fb.get(20, TimeUnit.SECONDS) ? 1 : 0));
        } finally { pool.shutdownNow(); }
    }
}
