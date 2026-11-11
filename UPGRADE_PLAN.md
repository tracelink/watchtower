# Watchtower Dependency Upgrade Plan

**Last updated:** 2026-08-31
**Status:** Tiers 1–4 are code-complete (manual verification tracked separately in
`MANUAL_VERIFICATION.md`). Tier 5 (Java 21/25 + Spring Boot 4.x) is now underway, split into
three slices to isolate JDK problems from Spring Boot problems — see the Tier 5 section below.
Slice 1 (Java 8 → 17, Spring Boot left at 2.7.18) is complete and verified as of 2026-08-31
(commit `28b6573`): 913/913 tests, both natively and via a full Docker build on the updated
base image. Slice 2 (Spring Boot 4.x + `javax`→`jakarta`, done atomically) is next.

All of Tier 1 through Tier 4 is now code-complete. Tiers 1–3, 4b, and 4c are fully
verified — deployed to the dev cluster 2026-08-30, manually checked in-browser: PMD/ESLint/
JSON/Regex rule designers all render and save correctly (ESLint's read-only fields, JS/JSON
syntax highlighting, and modal `.refresh()` behavior all confirmed), the version badge shows the
real deployed tag, and the Tier 3 active-tab highlight fix renders correctly. Tier 4a (PMD 6→7)
is also now complete — a full API migration plus a Flyway data migration, verified via a real
fixture-based violation test (green before and after) and the full reactor test suite
(913/913) — **but still pending the same kind of manual, in-browser/in-database verification the
other tiers already got**: this environment has no live database or browser, so Tier 4a hasn't
been checked against a real scan or the PMD rule designer UI yet. See Tier 4a below, especially
its "Still unverified, honestly" section, before treating it as fully done. The `flyway-mysql` fix and the
Flyway checksum validation were both confirmed live on 2026-08-28: the app was deployed to the
dev cluster and booted cleanly against real MySQL (Spring Boot runs Flyway `migrate` +
`validateOnMigrate` at startup, so a clean boot means checksums validated against that DB).
**Prod's `flyway:validate` is still independently unconfirmed** — this environment has no live
DB access to run it directly, and a clean dev boot doesn't stand in for a prod one. Pre-existing
unit test failures across the whole reactor are fixed, so the suite is a reliable regression
signal going forward.

**Version verification note:** every target version in this document was checked against
authoritative sources on 2026-08-27 — Maven Central's raw `maven-metadata.xml` (not the
`search.maven.org` search index, which was found to lag behind actual releases for several
artifacts here) and the npm registry API. Versions move fast; re-verify before executing any
tier that sits open for more than a few weeks.

---

## Table of Contents

1. [Project Context](#1-project-context)
2. [Vulnerability Summary](#2-vulnerability-summary)
3. [Upgrade Tiers](#3-upgrade-tiers)
   - [Tier 1 — Immediate Low-Risk Upgrades](#tier-1--immediate-low-risk-upgrades)
   - [Tier 2 — Spring Boot 2.4.5 → 2.7.18](#tier-2--spring-boot-245--2718)
   - [Tier 3 — Post-Spring Boot Upgrades](#tier-3--post-spring-boot-upgrades)
   - [Tier 4 — Planned (Separate Sprints)](#tier-4--planned-separate-sprints)
   - [Tier 5 — Future: Java 21 + Spring Boot 4.x](#tier-5--future-java-21--spring-boot-4x)
4. [Data Migration Risk Summary](#4-data-migration-risk-summary)
5. [Progress Tracker](#5-progress-tracker)
6. [Security Issues NOT Covered by Upgrades](#6-security-issues-not-covered-by-upgrades)
7. [Testing Strategy](#7-testing-strategy)

---

## 1. Project Context

### Overview

Watchtower is a Spring Boot 2.4.5 / Java 8 multi-module Maven project that acts as a security scanning orchestration tool. It aggregates results from multiple security scanners and presents findings through a web UI.

### Module Structure

| Module | Purpose |
|--------|---------|
| `watchtower-core` | Domain model, services, JPA entities, Flyway migrations, Thymeleaf templates |
| `watchtower-web` | Spring Boot application entry point, web-layer config, login/register templates |
| `watchtower-test` | Shared test utilities and fixtures used by all modules |
| `watchtower-module-pmd` | PMD static analysis scanner adapter |
| `watchtower-module-json` | JSON-based rule scanning (uses org.json) |
| `watchtower-module-checkov` | Checkov IaC scanner adapter (uses zip4j for result packaging) |
| `watchtower-module-eslint` | ESLint JavaScript scanner adapter |
| `watchtower-module-regex` | Regex-based custom rule scanner adapter |
| `watchtower-module-advisory` | Dependency advisory scanner adapter |
| `watchtower-maven-plugin` | Maven plugin (`watchtower-upload-scan`) for triggering scans from builds |
| `watchtower-cli` | Command-line interface entry point |

### Database Setup

- **Production DB:** MySQL, connected via `JDBC_URL` environment variable
- **DDL strategy:** `ddl-auto=none` — Hibernate does not touch the schema
- **Schema management:** Flyway, migrations V001 through V031 exist in `watchtower-core/src/main/resources/db/migration/`
- **Dev/Test DB:** H2 in-memory with `MODE=MySQL` (no data persistence between runs)

### Key Configuration Files

| File | Purpose |
|------|---------|
| `watchtower-web/src/main/resources/application.yaml` | Production config — contains `ddl-auto: none` |
| `watchtower-core/src/test/resources/application.yaml` | Test config — H2 in-memory datasource |

### Already-Completed Work

- **Sidebar performance fix:** The sidebar is pre-filtered in `WatchtowerMvcHandler` interceptor by authority before being passed to Thymeleaf, eliminating expensive SpEL evaluation on every template render.

---

## 2. Vulnerability Summary

**Snapshot date:** 2026-05-13  
**Source:** Snyk SCA scan

| Severity | Count |
|----------|-------|
| CRITICAL | 128 |
| HIGH | 752 |
| MEDIUM | 738 |
| LOW | 172 |
| **Total** | **1,790** |

**Affected packages:** 76

The vast majority of these vulnerabilities are resolved by the Spring Boot 2.4.5 → 2.7.18 upgrade (Tier 2), because that single change transitively updates Tomcat, Spring Framework, Spring Security, Logback, Jackson, SnakeYAML, and Netty. The remaining vulnerabilities are addressed by the targeted library upgrades in Tiers 1, 3, and 4.

---

## 3. Upgrade Tiers

---

### Tier 1 — Immediate Low-Risk Upgrades — ✅ COMPLETE

These upgrades are independent of each other and of the Spring Boot upgrade. Each is a simple version bump with no API changes. They can be applied in any order and do not require a coordinated release.

**Status:** Done in two passes. Pass 1 resolved the originally-flagged CVEs (commit
`4a8ddd9`). Pass 2 (this update) refreshed all four to their true current-latest stable
version, verified against Maven Central's raw `maven-metadata.xml` on 2026-08-27 — the plan's
original pass-1 targets were themselves already stale by the time they were written (org.json
alone was ~3 years behind). Full reactor test suite (907 tests, 12 modules) passes with zero
failures at these versions.

**Prerequisite (satisfied):** All existing unit tests pass before starting (`mvn test`). This
was not true when this plan was first drafted — 112 tests were failing or erroring across the
reactor. All were triaged and fixed (see [Testing Strategy](#7-testing-strategy)); the four
version bumps below were verified against that now-clean baseline.

---

#### 1a. org.json: 20200518 → 20260814

| Field | Detail |
|-------|--------|
| **Original version** | 20200518 |
| **Target version (verified latest, 2026-08-27)** | 20260814 |
| **CVEs fixed** | CVE-2023-5072 (DoS via crafted input), CVE-2022-45688 (DoS via malformed JSON), plus everything patched in the ~15 releases since 20231013 |
| **Severity** | HIGH |
| **Data migration risk** | None |

**Change:**

File: `watchtower-module-json/pom.xml`

```xml
<dependency>
    <groupId>org.json</groupId>
    <artifactId>json</artifactId>
    <version>20260814</version>
</dependency>
```

**Rationale for no API breakage:** org.json maintains a stable API across this whole range —
no deprecated methods were removed between 20200518 and 20260814. No `.java` source in
`watchtower-module-json` imports `org.json` directly (it's declared for `json-path`'s
pluggable JSON provider); the only direct consumers are four test classes in
`watchtower-core`, unaffected by this module's dependency version.

**Verification:**

```bash
mvn test -pl watchtower-module-json
```

---

#### 1b. commons-lang3: 3.8.1 → 3.20.0

| Field | Detail |
|-------|--------|
| **Original version** | 3.8.1 |
| **Target version (verified latest, 2026-08-27)** | 3.20.0 |
| **CVEs fixed** | CVE-2025-48924 (HIGH — Uncontrolled Recursion in `ToStringBuilder`), plus fixes in 3.19.0/3.20.0 |
| **Severity** | HIGH |
| **Data migration risk** | None |

**Change:**

File: root `pom.xml` — version property:

```xml
<commons.lang3.version>3.20.0</commons.lang3.version>
```

**Rationale for no API breakage:** Apache Commons Lang 3.x follows strict semantic versioning.
The full 3.8.1 → 3.20.0 range is additive changes and bug fixes; no public API removals.

**Verification:**

```bash
mvn test -pl watchtower-core,watchtower-cli,watchtower-module-regex
```

---

#### 1c. commons-io: 2.8.0 → 2.22.0

| Field | Detail |
|-------|--------|
| **Original version** | 2.8.0 |
| **Target version (verified latest, 2026-08-27)** | 2.22.0 |
| **CVEs fixed** | Several path traversal and resource leak CVEs across 2.9–2.14, plus everything patched through 2.22.0 |
| **Severity** | MEDIUM–HIGH |
| **Data migration risk** | None |

**Change:**

File: root `pom.xml` — version property:

```xml
<commons.io.version>2.22.0</commons.io.version>
```

**Rationale for no API breakage:** Commons IO 2.x maintains backward compatibility throughout
the 2.x line. All existing usage of `IOUtils`, `FileUtils`, and stream utilities remains
compatible at 2.22.0.

**Verification:**

```bash
mvn test -pl watchtower-core,watchtower-cli
```

---

#### 1d. zip4j: 2.10.0 → 2.11.6

| Field | Detail |
|-------|--------|
| **Original version** | 2.10.0 |
| **Target version (verified latest, 2026-08-27)** | 2.11.6 |
| **CVEs fixed** | Path traversal and zip-slip vulnerabilities patched in 2.11.x, plus 2.11.4–2.11.6 fixes |
| **Severity** | MEDIUM |
| **Data migration risk** | None |

**Change:**

File: root `pom.xml` — version property:

```xml
<zip4j.version>2.11.6</zip4j.version>
```

**Rationale for no API breakage:** Patch releases within the 2.x minor series (2.10.0 →
2.11.6). No public API changes. Note: there is an unrelated, much older `net.lingala:zip4j`
1.3.3 artifact under a *different* groupId (no `.zip4j` suffix) — do not confuse the two; this
project correctly uses `net.lingala.zip4j:zip4j`.

**Verification:**

```bash
mvn test -pl watchtower-core,watchtower-cli,watchtower-module-checkov
```

---

### Tier 2 — Spring Boot 2.4.5 → 2.7.18

This is the single highest-leverage change in the entire plan. Spring Boot 2.7.18 is the final Long-Term Support release of the 2.x line. It transitively resolves vulnerabilities in Tomcat, Spring Framework, Spring Security, Logback, Jackson Databind, SnakeYAML, and Netty with a single version bump.

**Spring Boot 2.7.x supports Java 8.** No JDK upgrade is required for this tier.

**Prerequisite:** All Tier 1 upgrades should be applied and tests passing before starting this.

---

#### 2a. Core Version Bump

**Change to make:**

File: root `pom.xml` — update the Spring Boot parent:

```xml
<!-- Before -->
<parent>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-parent</artifactId>
    <version>2.4.5</version>
    <relativePath/>
</parent>

<!-- After -->
<parent>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-parent</artifactId>
    <version>2.7.18</version>
    <relativePath/>
</parent>
```

---

#### 2b. What This Fixes (Transitive Updates)

Exact bundled versions below are read directly from the `spring-boot-dependencies:2.7.18` BOM
(verified 2026-08-27), not estimated ranges.

| Component | 2.4.5 version | 2.7.18 version (exact) | CVEs resolved |
|-----------|--------------|----------------|---------------|
| Tomcat | 9.0.45 | 9.0.83 | CRITICAL: 36, HIGH: 171 |
| Spring Framework | 5.3.6 | 5.3.31 | CVE-2023-20860 (Access Control Bypass) |
| Spring Security | 5.4.6 | 5.7.11 | CVE-2024-38821 (Missing Auth), CVE-2022-22978 (Auth Bypass) |
| Logback | 1.2.3 | 1.2.12 | RCE via JMX (CVE-2021-42550) |
| Jackson Databind (BOM) | 2.12.x | 2.13.5 | Multiple deserialization CVEs |
| SnakeYAML | 1.27 | 1.30 | CVE-2022-25857, CVE-2022-38749, CVE-2022-38750, CVE-2022-38751 |
| Netty | 4.1.x | 4.1.101.Final | Multiple HTTP request smuggling and DoS CVEs |
| H2 (test scope) | 1.4.200 | 2.1.214 | CVE-2022-23221 (RCE), CVE-2021-42392 (RCE) |
| Flyway | 7.x | 8.5.13 | — |
| Hibernate | 5.4.x | 5.6.15.Final | — |

**Note:** H2 2.1.214 (test scope only) is itself several years behind H2's current latest
(2.4.240, per Tier 3b) — Spring Boot's BOM pins an older H2 than what's independently
available. This is expected (Boot pins what it's tested against) and not a blocker, but if H2
2.1.214 turns out to have its own unresolved CVEs, overriding `<h2.version>` independently of
the Boot BOM is a safe, supported pattern.

---

#### 2c. Areas Requiring Attention

##### Flyway 7.x → 8.x

Flyway 8 bundled in Spring Boot 2.7 introduces stricter checksum validation.

**Action required before deploying to any environment:**

```bash
mvn flyway:validate -pl watchtower-web
```

If this command reports checksum mismatches, the migration files have been altered since they were first applied. Do not repair production checksums without understanding what changed. Investigate each mismatch individually.

##### Flyway 8.5.13 dropped bundled MySQL support (found live, 2026-08-27)

**This is a real, confirmed boot-time failure, not a hypothetical.** After Tier 2 shipped to the
dev cluster, the pod crash-looped with:

```
org.flywaydb.core.api.FlywayException: Unsupported Database: MySQL 8.4
	at org.flywaydb.core.internal.database.DatabaseTypeRegister.getDatabaseTypeForConnection
```

Root cause, verified by decompiling the actual jars in the local `.m2` cache (not by trusting
search results, which were inconsistent on this point): Flyway 7.1.1 and 8.0.5 both bundle
`MySQLDatabaseType` directly inside `flyway-core` and register it via
`META-INF/services/org.flywaydb.core.extensibility.Plugin`. **Flyway 8.5.13 — the version
Spring Boot 2.7.18's BOM manages — has zero MySQL classes and no MySQL entry in that plugin
file.** MySQL support moved out into a separate `org.flywaydb:flyway-mysql` artifact (new
`org.flywaydb.database.mysql` package, part of Flyway's post-8.5 "Community DB support"
split). Since `watchtower-core/pom.xml` only declared `flyway-core`, no registered
`DatabaseType` claimed "MySQL" at all — the error fires for *any* MySQL version, not
specifically 8.4; "8.4" was just what the connection string happened to report.

Confirmed `flyway-mysql:8.5.13`'s `handlesDatabaseProductNameAndVersion` does a plain
`databaseProductName.contains("MySQL")` check with no version gating, so it accepts MySQL 8.4
(or any other MySQL version) once present.

**Fix applied:** added the missing dependency to `watchtower-core/pom.xml`, right next to
`flyway-core`, with no explicit version — it inherits `${flyway.version}` (8.5.13) from Spring
Boot's BOM, which already manages `flyway-mysql` alongside `flyway-core`:

```xml
<dependency>
	<groupId>org.flywaydb</groupId>
	<artifactId>flyway-mysql</artifactId>
</dependency>
```

Verified via `mvn dependency:tree -Dincludes=org.flywaydb` that it resolves to 8.5.13
alongside `flyway-core`. Full reactor test suite re-run after the change (see Progress
Tracker below for result). **This does not replace the need to run `flyway:validate`
above** — that checks migration-file checksums, a separate concern from database-type
recognition.

**Confirmed fixed, 2026-08-28:** redeployed to the dev cluster with this dependency in place —
the pod booted cleanly with no `FlywayException`, and the app was manually tested working.
This also serves as the `flyway:validate` confirmation for that environment (see Tier 2
Progress Tracker below). Prod remains unconfirmed.

**Related false alarm, resolved 2026-08-28:** a report of Flyway being "stuck at 002" during
this same investigation was not a bug — Watchtower runs Flyway separately per scan module
(checkov/eslint/pmd/regex modules each only have V001–V002 migration files on disk, so they
correctly report version 002; the main app schema in `watchtower-core` is the one that runs
V001–V031). Multiple `DbMigrate`/`DbValidate` log blocks at startup, one per module, is
expected behavior, not a stuck migration.

##### Hibernate 5.4.x → 5.6.x

- `ddl-auto=none` means Hibernate will never alter the production MySQL schema. This protects against schema drift.
- Watch for behavioral changes in JPQL query interpretation between 5.4 and 5.6. The HQL parser became stricter about ambiguous path expressions.
- Run the full test suite and review any `QuerySyntaxException` or `SemanticException` failures carefully.

##### H2 1.4.200 → 2.x (Test Scope Only)

H2 2.x made SQL parsing significantly stricter and introduced new reserved keywords.

**Common failure patterns to watch for:**

- Column names or aliases that happen to be reserved words in H2 2.x (e.g., `VALUE`, `USER`, `NAME`)
- If any test datasource URL starts failing, try appending `;NON_KEYWORDS=VALUE` (or whatever keyword is conflicting) to the JDBC URL in `watchtower-core/src/test/resources/application.yaml`:

```yaml
# Example — only add NON_KEYWORDS if tests fail due to keyword conflicts
spring:
  datasource:
    url: jdbc:h2:mem:testdb;MODE=MySQL;NON_KEYWORDS=VALUE
```

- H2 is used in test scope only. No production data is at risk.

##### Spring Boot Property Changes in 2.7

- **`spring.profiles.active` split behavior:** In 2.4+, comma-separated profiles are no longer split automatically in some contexts. If profile activation behaves unexpectedly, check for this.
- **`spring.config.use-legacy-processing`:** This property (which could be set to `true` to restore 2.3 config behavior) was removed in 2.7. If it exists in any `application.yaml`, remove it.
- **Actuator endpoint defaults changed:** Several actuator endpoints that were enabled by default in 2.4 are now disabled. Review actuator configuration if the admin/monitoring endpoints are in use.

---

#### 2d. Verification Steps

```bash
# 1. Full test suite
mvn test

# 2. Flyway validation (critical before any deploy)
mvn flyway:validate -pl watchtower-web

# 3. Full build including integration tests
mvn verify

# 4. Check for dependency convergence issues
mvn dependency:tree -pl watchtower-web | grep -i "conflict\|omitted"
```

---

### Tier 3 — Post-Spring Boot Upgrades

These upgrades depend on the Spring Boot 2.7 upgrade being in place, or carry enough complexity that they should be done in their own focused sprint after Tier 2 is stable.

---

#### 3a. Thymeleaf: 3.0.12 → 3.1.5.RELEASE

| Field | Detail |
|-------|--------|
| **Current version** | 3.0.12.RELEASE |
| **Target version** | 3.1.5.RELEASE (verified latest on Maven Central, 2026-08-27 — this was already correct in the plan) |
| **CVEs fixed** | CVE-2026-40477 (CRITICAL — Template Injection), CVE-2026-40478 (CRITICAL — Template Injection), CVE-2026-41901 (CRITICAL — EL Injection), CVE-2021-43466 (HIGH — RCE) |
| **Data migration risk** | None |

**Important context:** Spring Boot 2.7 ships Thymeleaf 3.0.15 by default — not 3.1.x. To get 3.1.5, the version must be explicitly overridden in the root `pom.xml`.

**Changes to make:**

File: root `pom.xml` — add or update the version properties:

```xml
<properties>
    <!-- ... existing properties ... -->
    <thymeleaf.version>3.1.5.RELEASE</thymeleaf.version>
    <thymeleaf-extras-springsecurity5.version>3.1.5.RELEASE</thymeleaf-extras-springsecurity5.version>
</properties>
```

**Correction (2026-08-27):** the plan previously listed `thymeleaf-extras-springsecurity5` at
3.1.1.RELEASE — that's four patch versions behind. Both artifacts ship on the same release
train and should be kept in lockstep; the verified latest for both is 3.1.5.RELEASE.

**Breaking change — deprecated template variables:**

Thymeleaf 3.1 deprecated the following expression utility objects inside templates:

- `#request` (HttpServletRequest)
- `#response` (HttpServletResponse)
- `#session` (HttpSession)
- `#servletContext` (ServletContext)
- `#httpServletRequest` / `#httpSession` — the Spring-specific raw-servlet-access variants
  (distinct names from `#request`/`#session` above). **Not in the plan's original grep
  pattern** — found live in this codebase (see below) and confirmed via Thymeleaf's own issue
  tracker that these were also targeted for restriction/removal in 3.1, with full removal
  planned for 3.2.

These are now restricted. If any template uses these variables to access request attributes, session values, or servlet context data, those expressions will fail at render time.

**Templates to audit:**

Search all `.html` files under:

```
watchtower-core/src/main/resources/templates/
watchtower-web/src/main/resources/templates/
```

```bash
# Find any template using the deprecated expression objects (all known variants)
grep -r "#request\b\|#response\b\|#session\b\|#servletContext\b\|#httpServletRequest\|#httpSession" \
  watchtower-core/src/main/resources/templates/ \
  watchtower-web/src/main/resources/templates/
```

For each hit, refactor to pass the required data via the Spring MVC `Model` object from the controller, rather than accessing it directly in the template.

**Found and fixed, 2026-08-28:** one hit — `watchtower-core/src/main/resources/templates/rules/designer.html:23` used
`${#httpServletRequest.getRequestURI().contains(optionKey.toLowerCase())}` to highlight the
active designer tab. This wasn't just a deprecation warning — it broke a full-context
`@SpringBootTest`/MockMvc render (`RuleDesignerControllerTest.testGetLangDesigner`) with
`EL1011E: Attempted to call method getRequestURI() on null context object`, i.e. the expression
object itself resolved to null under thymeleaf-spring5 3.1.5. Fixed by having
`RuleDesignerController.getDesignerByModule` add the current designer as a model attribute
(`currentDesigner`) and comparing against that in the template instead of parsing the request
URI. Full reactor re-run clean after the fix: 907/907 tests, 0 failures, 0 errors, all 12
modules. The original narrower grep (`#request\|#response\|#session\|#servletContext`, without
word boundaries) would have reported zero hits on this exact codebase — re-run the updated
pattern above if auditing templates again, e.g. before Tier 5.

**Verification:**

```bash
mvn test

# Then manually smoke-test every page in the web UI:
# - Login page
# - Dashboard / sidebar
# - Scan results view
# - Admin panel
# - Rule management
# - User management
```

---

#### 3b. H2 2.x Test Compatibility Verification

This is a verification task, not an active upgrade — H2 2.x arrives transitively via the Spring Boot 2.7 upgrade. However, it warrants its own checklist item because test failures from H2 2.x strictness can be subtle.

**What to look for:**

1. `JdbcSQLSyntaxErrorException` in test output — indicates a SQL keyword conflict or syntax incompatibility
2. `SchemaObjectNotFoundException` — indicates a table or column that H2 2.x can no longer find (sometimes caused by case-sensitivity differences)
3. Flyway migration failures in test context — H2 2.x is stricter about DDL than 1.4.200

**Fix pattern:**

If keyword conflicts arise, amend the test datasource URL in `watchtower-core/src/test/resources/application.yaml`:

```yaml
spring:
  datasource:
    url: jdbc:h2:mem:testdb;MODE=MySQL;DB_CLOSE_DELAY=-1;NON_KEYWORDS=VALUE,NAME
```

Add only the specific keywords that are conflicting; do not add blanket exclusions.

**Verification:**

```bash
mvn test -pl watchtower-core,watchtower-test
```

---

### Tier 4 — Planned (Separate Sprints)

These upgrades involve breaking API changes that require code-level changes beyond a version bump. Each should be scoped and executed as a dedicated sprint.

---

#### 4a. PMD: 6.36.0 → 7.x — ✅ COMPLETE, PENDING MANUAL SCAN VERIFICATION

| Field | Detail |
|-------|--------|
| **Previous version** | 6.36.0 |
| **New version** | 7.27.0 (`pmd-core`, `pmd-java`, `pmd-scala_2.12`, `pmd-scala_2.13`, `pmd-xml`, `pmd-test`) |
| **CVEs fixed** | Multiple MEDIUM severity CVEs in 6.36.0 |
| **Affected module** | `watchtower-module-pmd` (11 files) |
| **Data migration** | **Yes — done.** `watchtower-module-pmd/src/main/resources/db/pmd/V003__Fix_Stale_PMD_XPathRule_Class.sql` |

**Safety net added first, 2026-08-30, before touching any PMD code:**
`PMDScannerFixtureViolationTest` runs `PMDScanner.scan()` end to end against a real `pom.xml`
fixture and a real rule (`RestrictNodesUnderProject`), asserting an actual detected violation at
the expected line. Confirmed passing against the 6.36.0 baseline first, then used as the
pass/fail gate for the whole migration — this is what the earlier scoping pass flagged as
missing, since neither `PMDScannerTest` (empty temp directory, no source file) nor
`PMDReportTest` (fully mocked `Report`) would have caught a silent drop to zero violations.

**What changed, file by file** (all four rewrites anticipated by the scoping pass, plus two more
found only by actually doing the migration):

1. **`PMDScanner.scan`** — replaced `PMD.runPmd(config)` + serializing rules to a temp ruleset
   XML file (`RuleSetWriter`) + `setRuleSets(pathString)` with `PmdAnalysis.create(config)` +
   `pmd.addRuleSet(RuleSet)` — PMD 7's embedding API takes a `RuleSet` **object** directly, so the
   temp-file round-trip is gone entirely, not just rewritten.
2. **`PMDRenderer`** — replaced the PMD 6 `start()`/`report.start()`/`end()` lifecycle (a mutable
   `report` field inherited from `AbstractAccumulatingRenderer`) with the new abstract
   `outputReport(Report)`, called once with the final accumulated, immutable `Report`. Defaults
   to an empty `Report.buildReport(l -> {})` so `createReport()` is still safe to call even if
   `outputReport` is never invoked (e.g. zero files scanned).
3. **`PMDRuleDesigner.getPMDXPathReport`** — re-expressed as a `PmdAnalysis` session over an
   in-memory `TextFile.forCharSeq(code, fileId, languageVersion)`, reusing `PMDReport` for the
   result via `performAnalysisAndCollectReport()`. `XPathRule` needed its constructor call
   changed too — see point 5.
4. **`PMDRuleDesigner.getPMDAST`** — same `PmdAnalysis`/`TextFile` approach, but for parsing
   only: a throwaway rule (`ASTCapturingRule`) whose `apply()` just captures the root node PMD
   hands it, walked afterward with the existing `PMDASTGenerator`. **Two non-obvious fixes were
   required to make this work, found only by testing it, not by reading signatures:**
   - `AbstractRule`'s default target selector does **not** target the root node — confirmed by
     adding a diagnostic print inside `apply()` and seeing it never fire. Needed an explicit
     `buildTargetSelector() { return RuleTargetSelector.forRootOnly(); }` override.
   - `Rule.deepCopy()` (confirmed via `javap -c`, reading the actual bytecode) constructs a
     **brand new instance via reflection** (`getClass().getDeclaredConstructor().newInstance()`)
     before invoking any rule, copying only the standard `Rule` interface properties
     (name/language/message/etc. via their getters/setters). A custom subclass field like
     "the node I captured" is invisible to the caller — PMD invokes the copy, not the instance
     you kept a reference to. Fixed by moving the captured node into a **static** field on
     `ASTCapturingRule` (shared by construction across the original and any copy) and making
     `getPMDAST` `synchronized` against it, since only one such capture may be in flight at a
     time. Anyone writing a stateful custom PMD 7 rule in this codebase should expect this same
     trap.
5. **`PMDRuleService.makeRuleFromDto`** — `net.sourceforge.pmd.rules.RuleBuilder` is removed with
   no replacement class; rebuilt as direct reflection (`Class.forName(...).getDeclaredConstructor().newInstance()`)
   plus the `Rule` interface's own setters, which is what `RuleBuilder` did internally anyway.
   **One special case found only by running the tests, not by reading docs:** `XPathRule` itself
   has **no no-arg constructor** in PMD 7 — it's now `XPathRule(XPathVersion, String)`, immutable,
   expression supplied up front (`setXPath(String)` is also gone). Since
   `PMDDesignerController` always creates custom rules as `XPathRule` with the expression stored
   as a property named `"xpath"`, `instantiateRule(...)` special-cases that one class: pulls the
   `"xpath"` property out and calls the real constructor instead of blind no-arg reflection.
6. **`BasicPomRule`** — `AbstractXmlRule` no longer provides a recursive `visit(XmlNode, RuleContext)`
   dispatcher to override (confirmed: PMD 7's version is abstract with only a no-arg
   constructor); `BasicPomRule` now implements `apply(Node, RuleContext)` itself and does its own
   recursion into `node.children()`. Also replaced Jaxen-based
   `XmlNode.findChildNodesWithXPath(...)` (removed entirely in PMD 7, which moved its own XPath
   engine to Saxon but doesn't expose it for ad-hoc DOM queries) with the JDK's own
   `javax.xml.xpath` running directly against the raw `org.w3c.dom.Node` from `XmlNode.getNode()`
   — zero new dependencies, and sidesteps the whole Jaxen-vs-Saxon question by not depending on
   PMD's internal engine for this at all.

**Confirmed package moves** (via `unzip -l`/`javap` against the real 7.27.0 jars): `Rule`,
`RuleSet`, `RulePriority`, `RuleContext`, `Report` moved from top-level `net.sourceforge.pmd`
into `net.sourceforge.pmd.lang.rule.*` / `net.sourceforge.pmd.reporting.*`; `XPathRule` moved to
`net.sourceforge.pmd.lang.rule.xpath.XPathRule`; the xpath `Attribute` class moved from
`lang.ast.xpath` to `lang.rule.xpath`; `RuleSetLoader`/`RuleSetWriter` moved to `lang.rule.*`.
`PropertyDescriptor.valueFrom(String)` is gone, replaced by `desc.serializer().fromString(...)`.
`PropertyDescriptor`/`PropertyFactory`, `Node`, `ParseException`, `Language`, `LanguageRegistry`
(now instance-based: `LanguageRegistry.PMD.getLanguageByFullName(...)`, no more static
`findLanguageByTerseName`), `LanguageVersion`, `JavaLanguageModule`/`ScalaLanguageModule`/`XmlLanguageModule`
(now expose `getInstance()` rather than public `NAME`/`TERSE_NAME` constants), `AbstractXmlRule`,
`XmlNode`, `Renderer`, `AbstractAccumulatingRenderer` all kept their existing package paths.

**Flyway data migration:** `watchtower-module-pmd/src/main/resources/db/pmd/V003__Fix_Stale_PMD_XPathRule_Class.sql`
rewrites any `pmd_rules.rule_class` value matching the pre-move `XPathRule` FQCN to the new one —
the one confirmed-stale case, since `PMDDesignerController` always wrote the old FQCN into every
UI-created custom rule. **Important gotcha hit while writing this:** `pmd_rules` does **not**
live in `watchtower-core`'s main migration history (`db/migration/`, V001–V031) — it has its own
separate per-module Flyway history at `watchtower-module-pmd/src/main/resources/db/pmd/`
(V001–V002 before this). Putting the fix in the wrong folder compiles fine but fails at Flyway
migrate time with `Table "PMD_RULES" not found` — caught immediately by the H2 test suite, but
worth remembering for any future per-module data migration in this repo (see also the
"Flyway per-module migrations" project memory from the "stuck at 002" investigation).
**Not audited:** whether any *other* stored `rule_class` value besides `XPathRule` references a
class PMD 7 also moved — no other custom rule class name is written by any code path in this
repo, but if a `pmd_rules` row was ever created outside this codebase's own UI/API (direct DB
insert, import script, etc.) with a different class name, it isn't covered by V003.

**Still unverified, honestly:**
- **No live database or browser in this environment.** Everything above is verified by
  compilation, a real fixture-based violation test, and the full reactor test suite
  (913/913, 0 failures, 0 errors, all 12 modules) — but not by an actual scan against a real
  repository, and not by clicking through the PMD rule designer UI. Before this ships: run a
  real PR/upload scan through a ruleset containing both a **provided** rule and a **custom**
  rule, and open the PMD rule designer and confirm the AST view and XPath match-testing still
  work end to end in a browser.
- **Provided rules still resolve by name, live, at scan time — this was never fixed, because
  it isn't fixable in code.** `PMDRuleService.makeRuleFromDto` looks up a provided rule via
  `getPMDOriginalRulesMap().get(provided.getName())`, rebuilt fresh from
  `new RuleSetLoader().getStandardRuleSets()` (whatever PMD 7.27.0 ships) on first use. Any
  `pmd_rules` row referencing a rule name PMD 7 renamed or removed will throw
  `RuleNotFoundException` the next time a scan runs that rule — not at boot, not at deploy,
  silently until then. There's no static list in this repo of which provided-rule names are
  actually configured in production to check against PMD 7's changelog before shipping this;
  that check has to happen against the real `pmd_rules` table.
- **The Jaxen→`javax.xml.xpath` port for `BasicPomRule.getFromProperty`'s `${project.x.y}`
  property-resolution feature is unverified beyond "compiles and preserves the same query
  string."** This code path is dormant in production today (`RestrictNodesUnderProject`, the only
  shipped concrete rule, never enables `RESOLVE_PROPERTIES`), so the fixture test doesn't
  exercise it, and the original query string (`"/" + path + "/child::text"`, missing the
  `()` a strict XPath `text()` node-test would need) may have only ever worked because Jaxen was
  lenient about it. If this feature is ever turned on for a real rule, verify it manually first.
- **PMD 7's multi-value property delimiter changed from `|` to `,`** (per the official migration
  guide). `RestrictNodesUnderProject.ALLOWED_SUBNODES` is a list-typed property
  (`PropertyFactory.stringListProperty`) that isn't exposed through the rule-designer UI today,
  but if any `pmd_rules`/`pmd_properties` row was ever hand-created with a `|`-delimited value
  for it (or any other list-typed custom-rule property), it will now parse as a single value
  containing literal `|` characters instead of a list. Not something this migration could fix
  blind — worth a one-time grep of the real `pmd_properties` table for `|` in stored values
  before relying on any multi-value custom PMD property.

**Reference:** [PMD 7 Migration Guide](https://pmd.github.io/pmd/pmd_userdocs_migrating_to_pmd7.html) — the guide itself notes it "might be incomplete"; most of what's above came from `javap`/bytecode inspection and empirical testing, not the guide.

---

#### 4b. Luxon (webjar): 1.26.0 → 3.x — ✅ COMPLETE AND VERIFIED

| Field | Detail |
|-------|--------|
| **Current version** | 1.26.0 |
| **Target version** | 3.7.2 (re-verified against Maven Central's `maven-metadata.xml` for `org.webjars.npm:luxon` on 2026-08-29 — still the latest release) |
| **CVEs fixed** | CVE-2023-22467 (HIGH — ReDoS via crafted date string) |
| **Data migration risk** | None |

**Why this was expected to be Tier 4:**

Luxon 2.x and 3.x introduced breaking API changes from 1.x — most notably `DateTime.local()` renamed to `DateTime.now()`. In practice, this codebase's actual footprint turned out much smaller than the plan anticipated.

**Actual scope found, 2026-08-29:** only 3 files reference Luxon at all, and only one of
them calls its API:

- `watchtower-core/src/main/resources/static/scripts/localizetime.js` — the only real usage:
  `luxon.DateTime.fromMillis(Number(html)).toLocaleString(datetimeopts)`. Neither
  `fromMillis` nor `toLocaleString` were renamed or changed across 1.x → 3.x; confirmed
  present in the 3.7.2 webjar's `build/global/luxon.js` by inspecting the downloaded jar
  directly. `DateTime.local()` (the actual breaking rename) is **not used anywhere** in this
  codebase, so that breaking change doesn't apply here.
- `watchtower-core/src/main/resources/templates/fragments/htmlhead.html` — just the
  `<script src="/webjars/luxon/{version}/build/global/luxon.js">` tag; this fragment is
  included by every page (`container.html`, `login.html`, `login-sso.html`, `register.html`,
  `error.html`), so the version bump takes effect app-wide.
- `admin/encryption.html` — false positive from the original grep pattern; it matched the
  Java property name `lastRotationDateTime`, not any Luxon API call.

**Changes made:**

1. `watchtower-core/pom.xml`: `<version>1.26.0</version>` → `<version>3.7.2</version>` for
   `org.webjars.npm:luxon`
2. `fragments/htmlhead.html`: script `src` path bumped to `/webjars/luxon/3.7.2/build/global/luxon.js`
   (verified this exact path still exists in the 3.7.2 jar — webjar internal layout unchanged)

No JavaScript code changes were needed. `mvn test` (watchtower-core + dependents): 680/680
passing, 0 failures, 0 errors. **Still outstanding:** manual browser check of any page showing
a localized timestamp (e.g. Admin → Encryption key rotation dates, scan history datatables) —
automated tests don't execute the JS date-formatting path in a real browser.

**Reference:** [Luxon Changelog](https://moment.github.io/luxon/#/changelog)

---

#### 4c. CodeMirror (webjar): 5.60.0 → 6.x — ✅ COMPLETE AND VERIFIED

| Field | Detail |
|-------|--------|
| **Previous version** | 5.60.0 (webjar `org.webjars.npm:codemirror`) |
| **New approach** | Not a webjar anymore — CodeMirror 6 is bundled at dev-time from real npm packages into one self-contained static asset, checked into the repo (see below) |
| **CVEs fixed** | MEDIUM severity CVE in CodeMirror 5.60.0 |
| **Data migration risk** | None |

**Why this needed an architecture decision, not just a version bump:** CodeMirror 6 has no
`fromTextArea` API (a ground-up rewrite around `EditorView`/`EditorState`/extensions) and ships
as ESM `@codemirror/*` npm packages — this project has no JS bundler, only raw `<script src>`
tags plus webjars. Two options were considered: bundle locally at dev/build time (no new runtime
dependency, no CSP change), or load from a public CDN via `<script type="module">` + an import map
(no bundler needed, but a runtime dependency on an external CDN and a CSP `script-src` change for
a security-scanning product). **Chose the local bundle** — Node/npm are already part of this
project's Docker build (used for the ESLint module today), so this isn't new tooling from
scratch.

**What was built, 2026-08-29:**

- New source project: `watchtower-core/src/main/frontend/codemirror6/` — a small npm project
  (`package.json` + `src/index.js`) with `@codemirror/state`, `@codemirror/view`,
  `@codemirror/commands`, `@codemirror/language`, `@codemirror/lang-javascript`,
  `@codemirror/lang-json` as real dependencies (versions resolved by `npm install`, not
  hand-typed), and `esbuild` to bundle them.
- `src/index.js` implements a **compatibility shim**: a global `CodeMirror.fromTextArea(textarea, options)`
  matching only the exact subset of the CodeMirror 5 API actually used across this repo's 5
  designer scripts (`pmd-designer.js`, `eslint-designer.js`, `eslint-editor.js`,
  `json-designer.js`, `regex-designer.js` — verified by reading all five): options
  `lineNumbers`, `mode` (`"javascript"` / `"json"` / unset), `readOnly`; methods `getValue()`,
  `setValue()`, `setSize()`, `refresh()`. **This means none of those 5 designer scripts needed
  to change at all** — only the one shared script reference in `RuleDesignerModelAndView.java`
  (used by all 4 modules' rule designer pages) was swapped from the CodeMirror 5 webjar path to
  `/scripts/codemirror-bundle.js`, and the now-unneeded `addStyleReference(...)` call was removed
  (CM6 injects its own `<style>` tags at runtime, unlike CM5).
- The shim also keeps the original `<textarea>`'s value in sync on every edit
  (`EditorView.updateListener`), matching CM5's `fromTextArea` behavior — this matters because
  `eslint-designer.js`'s save-rule modal reads `$("#sourceCode").val()` directly via jQuery on the
  original textarea element, not through the editor object.
- Built via `npm run build` → `esbuild --bundle --minify --format=iife`, output committed
  directly to `watchtower-core/src/main/resources/static/scripts/codemirror-bundle.js`
  (**388.9kb minified**, down from 779.4kb unminified). `node_modules/` is gitignored; the bundle
  itself is a normal static resource Maven already packages, same as any other file under
  `src/main/resources/static/`.
- Removed the now-dead `org.webjars.npm:codemirror:5.60.0` dependency from
  `watchtower-core/pom.xml` (confirmed nothing else referenced it).

**Deliberate scope tradeoff:** the bundle is built once and its output committed, rather than
wired into the Maven/Docker build pipeline to rebuild automatically on every `mvn package`. This
avoids adding a new network-dependent (npm registry) step to the Maven build path, which today has
none (the Dockerfile's existing `npm install` for ESLint happens in a later, separate stage). The
tradeoff: if `src/index.js` is edited later, `npm run build` (from
`watchtower-core/src/main/frontend/codemirror6/`) must be re-run and the output re-committed —
there's no CI check today that would catch a forgotten rebuild. Wiring this into the build (e.g.
via `frontend-maven-plugin` or `exec-maven-plugin` bound to `generate-resources`) is a reasonable
follow-up if this bundle needs to change often, but wasn't done here to keep this change's blast
radius contained.

**Automated verification done, and its real limit:** added `smoketest.js` (`npm test`), a headless
jsdom-based check (no real browser is available in this environment) covering construction,
`getValue`/`setValue` round-trip + textarea sync-back, `setSize`, `refresh`, `readOnly`, and both
language modes actually used (`javascript`, `json`) — all pass. **This is not a substitute for
manual browser verification.** jsdom lacks real layout/rendering, so it cannot confirm the editor
actually displays correctly, that typing/keyboard shortcuts behave as expected, or that it renders
correctly inside a Bootstrap modal (the `.refresh()` call exists specifically for that CM5 quirk;
its CM6 equivalent, `view.requestMeasure()`, is untested against a real modal open/close cycle).
Full reactor `mvn test`: 912/912, 0 failures, 0 errors — but that suite doesn't render Thymeleaf
output in a browser either, so it doesn't cover the editors visually or interactively.

**Before shipping, manually verify in a browser** (open each module's Rule Designer page — PMD,
ESLint, JSON, Regex — logged in with rule-designer privilege): the editor renders with line
numbers, typing works, syntax highlighting appears for the ESLint designer's JS/JSON fields, the
"Save Rule" modal correctly captures the editor's content, and the `#save-rule-modal` /
`#savePmdRuleModal` / etc. flows still populate their hidden form fields correctly on submit.

**Reference:** [CodeMirror 6 Migration Guide](https://codemirror.net/docs/migration/)

---

### Tier 5 — Future: Java 21 + Spring Boot 4.x

This is a major version migration requiring significant cross-cutting code changes. It should be planned as a dedicated multi-sprint effort after all lower tiers are stable.

**⚠️ Target changed from the original plan (2026-08-27 revision).** The original plan targeted
"Java 17 + Spring Boot 3.x." As of 2026-08-27, **Spring Boot 3.x's entire OSS support ended on
2026-06-30** (final release was 3.5.16) — landing this migration on 3.x would mean shipping on
an already-dead branch. Spring Boot 4.x is current (verified latest: **4.1.1**, with 4.2.0-M1
already in milestone). This tier now targets **Spring Boot 4.x** directly.

**This is a bigger lift than the original Tier 5 scoped for.** Skipping the 3.x line entirely
means this migration must absorb **both** Spring Boot 3.0's breaking changes (javax→jakarta,
`WebSecurityConfigurerAdapter` removal — these were never applied to this codebase, since it's
jumping straight from 2.4.5) **and** whatever Spring Boot 4.0 changes on top of that. Budget
for this accordingly; it is not a drop-in re-target of the same amount of work.

**Prerequisites:**
- A JDK adopted for all build and runtime environments — **Java 17 is the hard minimum** for
  Spring Boot 4.0, but Spring Framework 7.0 (which Boot 4.1 bundles) explicitly recommends
  Java 21 or Java 25 over 17. Java 17 itself loses Oracle Premier Support on 2026-09-30 (next
  month, as of this writing) — extended/paid support continues to 2029, but free security
  patches stop. **Recommendation: target Java 21 (LTS, supported until ~2026-09 for free
  updates, longer via Temurin/other vendors) or Java 25 (current LTS, released 2025-09) rather
  than 17**, given this migration already requires a full JDK upgrade — the incremental cost of
  landing on a newer LTS instead of the one about to lose free support is low.
- Java 8 is not supported by Spring Boot 4.x (nor was it by 3.x)

---

#### Key Breaking Changes

##### javax.* → jakarta.* Package Rename

Spring Boot 3+ is built on Jakarta EE 9+, which renamed all `javax.*` packages to `jakarta.*`.
This still applies going straight to 4.x (Boot 4 continues on Jakarta EE, it did not revert
this). This affects every Java source file that imports:

- `javax.persistence.*` → `jakarta.persistence.*`
- `javax.servlet.*` → `jakarta.servlet.*`
- `javax.validation.*` → `jakarta.validation.*`
- `javax.annotation.*` → `jakarta.annotation.*`
- `javax.transaction.*` → `jakarta.transaction.*`

This is a mechanical find-and-replace across all source files, but it must be done carefully and verified with compilation + tests.

```bash
# Estimate scope before starting
grep -r "javax\." watchtower-core/src/main/java \
  watchtower-web/src/main/java \
  watchtower-module-*/src/main/java | wc -l
```

##### Spring Security 7.x Configuration Overhaul

Spring Boot 4.1.1 bundles **Spring Security 7.1.1** (verified from the Boot 4.1.1 BOM,
2026-08-27) — two majors ahead of this codebase's current 5.4.6. `WebSecurityConfigurerAdapter`
was already removed as of Security 6.0 and remains removed in 7.x. Security configuration must
use the `SecurityFilterChain` bean approach:

```java
// Old pattern (Spring Security 5.x, current in this codebase):
@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception { ... }
}

// New pattern (Spring Security 6.x/7.x):
@Configuration
public class SecurityConfig {
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception { ... }
}
```

Re-check the [official Spring Boot 4.0 Migration Guide](https://github.com/spring-projects/spring-boot/wiki/Spring-Boot-4.0-Migration-Guide)
at execution time for anything Security 7.x changes beyond what Security 6.x already required
— this plan hasn't independently verified there are zero further Security 7.x-specific
breaking changes on top of the 6.x baseline above.

##### Thymeleaf Spring Security Extras

- Verified 2026-08-27: the correct artifact for Spring Boot 4.x + Spring Security 7.x is still
  **`thymeleaf-extras-springsecurity6`** (latest 3.1.5.RELEASE) — there is no
  `thymeleaf-extras-springsecurity7` artifact on Maven Central. The "6" in the artifact name
  tracks Spring Security's taglib integration generation, not a strict 1:1 major-version pin;
  it remains the correct dependency for Security 7.x.
- Change artifact ID from `thymeleaf-extras-springsecurity5` to `thymeleaf-extras-springsecurity6` in `pom.xml`, version `3.1.5.RELEASE`

##### Hibernate 7.x

- Spring Boot 4.1.1 bundles **Hibernate 7.4.5.Final** (verified from the BOM) — not 6.x as the
  original plan assumed, since that assumption was written for a 3.x target
- `ddl-auto=none` protects the MySQL schema from any Hibernate DDL changes regardless of
  Hibernate version
- JPQL/HQL dialect and query parsing has changed again between 5.6 (current) → 6.x → 7.x — test
  all queries; expect more surface area of behavior change than a straight 5.6→6.x move would
  have had, since this now spans two major Hibernate versions
- Some `@Column` and `@Table` annotation behaviors changed across both Hibernate majors; review
  entity classes

##### Other Bundled Versions (Spring Boot 4.1.1 BOM, verified 2026-08-27)

| Component | Version |
|-----------|---------|
| Spring Framework | 7.0.9 |
| Spring Security | 7.1.1 |
| Tomcat | 11.0.24 |
| Hibernate | 7.4.5.Final |
| H2 (test scope) | 2.4.240 |
| Flyway | 12.4.0 |
| JUnit Jupiter | 6.0.3 |
| Mockito | 5.23.0 |

Flyway jumps from 7.x/8.x (Tier 2) all the way to 12.x here — re-run the checksum-validation
guidance from Tier 2 (`mvn flyway:validate`) again at this tier; do not assume Tier 2's
validation covers this jump too.

##### Other Changes

- `spring-boot-properties-migrator` can be added as a temporary runtime dependency to detect deprecated property keys
- Actuator security defaults have changed across both Boot 3 and Boot 4 — review from scratch rather than diffing against 2.4.5's behavior
- Spring MVC's `HandlerInterceptorAdapter` (deprecated since Spring 5.3, already gone before Boot 3) — interceptors must implement `HandlerInterceptor` directly (check `WatchtowerMvcHandler`)

---

## 4. Data Migration Risk Summary

| Upgrade | Production MySQL Risk | Test H2 Risk | Action Required |
|---------|----------------------|--------------|-----------------|
| Tier 1: org.json, commons-lang3, commons-io, zip4j | None | None | Version bump only — ✅ done, verified against a 907-test green baseline |
| Tier 2: Spring Boot 2.4 → 2.7 | None (`ddl-auto=none`) | Low (SQL strictness in H2 2.x) | Run `flyway:validate`; fix H2 2.x test failures |
| Tier 3a: Thymeleaf 3.0 → 3.1 | None | None | Audit templates for deprecated expression objects |
| Tier 3b: H2 1.4 → 2.x (via Boot) | None (not used in prod) | Low | Fix any test SQL parsing failures |
| Tier 4a: PMD 6 → 7 | None | None | Config format migration; PMD API rewrite |
| Tier 4b: Luxon 1.26 → 3.x | None | None | JavaScript API migration |
| Tier 4c: CodeMirror 5 → 6 | None | None | Full JS integration rewrite |
| Tier 5: Java 17+ + Spring Boot 4.x | None (`ddl-auto=none`, Flyway) | Medium–High (two Hibernate majors' worth of query-parsing changes, not one) | `javax` → `jakarta` migration; Security config rewrite; re-run `flyway:validate` against the 8.x→12.x jump |

**Key insight:** Because `ddl-auto=none` is set for production and Flyway controls all schema changes through versioned migration scripts (V001–V031), no dependency upgrade in Tiers 1–4 can cause production schema drift. The database schema is decoupled from the ORM layer.

---

## 5. Progress Tracker

### Completed

- [x] Sidebar SpEL performance fix — `WatchtowerMvcHandler` pre-filters sidebar by authority before passing to template, eliminating expensive SpEL evaluation on every page render

### Prerequisites

- [x] **Fix currently failing unit tests** — Done. 112 tests were failing/erroring across the
  reactor when this plan was first drafted; all were triaged and fixed (see
  [Testing Strategy](#7-testing-strategy) for the breakdown and root causes). Full reactor is
  now 907/907 passing, 0 failures, 0 errors, across all 12 modules.

```bash
# Baseline is now clean — this should return 0 for FAIL/ERROR going forward
mvn test 2>&1 | grep -E "FAIL|ERROR|Tests run"
```

### Tier 1 — Immediate Low-Risk Upgrades — ✅ COMPLETE

- [x] org.json: `20200518` → `20260814` (file: `watchtower-module-json/pom.xml`)
- [x] commons-lang3: `3.8.1` → `3.20.0` (file: root `pom.xml`, property `commons.lang3.version`)
- [x] commons-io: `2.8.0` → `2.22.0` (file: root `pom.xml`, property `commons.io.version`)
- [x] zip4j: `2.10.0` → `2.11.6` (file: root `pom.xml`, property `zip4j.version`)
- [x] Verify all Tier 1 tests pass: `mvn test` — 907/907, 0 failures, 0 errors

### Tier 2 — Spring Boot 2.4.5 → 2.7.18 — ✅ COMPLETE

- [x] Update Spring Boot parent version in root `pom.xml`: `2.4.5` → `2.7.18`
- [x] Remove any `spring.config.use-legacy-processing=true` property if present in any `application.yaml` — N/A, property was never present in this codebase
- [x] Run `mvn test` — fix any H2 2.x SQL failures — no H2 SQL failures; found and fixed 3
      unrelated real compatibility breaks instead (see below)
- [x] Run `mvn flyway:validate -pl watchtower-web` (or equivalent) — **confirmed 2026-08-28 for
      dev**: deployed to the dev cluster; Spring Boot runs Flyway `migrate` +
      `validateOnMigrate` at startup, and the pod booted cleanly with no checksum errors,
      confirming migration integrity against that environment's live MySQL. **Prod is still
      unconfirmed** — this environment has no prod DB access to verify independently, and the
      dev boot doesn't cover it. Separately, the `prdtest` RDS schema-drift issue (V032 vs.
      master's V031, plus duplicate rows) mentioned here previously was unrelated to this Tier's
      changes and has since been resolved by the user (reverted to V031, duplicates cleaned up,
      2026-08-27).
- [x] Run `mvn verify` — full build with integration tests — BUILD SUCCESS, all 12 modules,
      907/907 tests passing
- [x] Review actuator endpoint configuration for any behavioral changes — N/A, this project does
      not depend on `spring-boot-starter-actuator` anywhere (verified via full-codebase search)
- [x] **Fixed a live boot failure found post-deploy (2026-08-27):** the dev-cluster pod
      crash-looped on `FlywayException: Unsupported Database: MySQL 8.4` because Flyway 8.5.13
      (Spring Boot 2.7.18's managed version) dropped bundled MySQL support out of `flyway-core`
      into a separate `flyway-mysql` artifact that was never added as a dependency — see
      "Flyway 8.5.13 dropped bundled MySQL support" above for full root-cause detail. Fixed by
      adding `org.flywaydb:flyway-mysql` (no explicit version — inherits 8.5.13 from the same
      Spring Boot BOM) to `watchtower-core/pom.xml`. **Confirmed fixed 2026-08-28**: redeployed
      with the fix in place, pod booted cleanly with no `FlywayException`, app manually tested
      working.

**Real compatibility fixes required (none anticipated by the original plan):**
1. `mysql:mysql-connector-java` → `com.mysql:mysql-connector-j` (`watchtower-core/pom.xml`) —
   Spring Boot's BOM renamed the managed MySQL driver coordinates within the 2.7.x line itself
   (2.7.0 still managed the old coordinates; 2.7.18 only manages the new ones), so the
   version-less dependency declaration stopped resolving
2. `KeyRotationServiceTest.TestRepositoryInformation` needed two new method implementations —
   `getDomainTypeInformation()` and `getIdTypeInformation()` — added to Spring Data Commons'
   `RepositoryMetadata` interface between 2.4.5 and 2.7.18
3. `OidcAuthServiceTest` — Spring Security 5.7.x validates `userNameAttributeName` more
   strictly than 5.4.6 did, and the test's manually-built `ClientRegistration` didn't set it;
   fixed by adding it and removing the test's unused `userInfoUri` (which was newly triggering
   a real, unmocked outbound HTTP call once the attribute-name validation passed)

### Tier 3 — Post-Spring Boot Upgrades — ✅ COMPLETE AND VERIFIED

- [x] Thymeleaf: Added `<thymeleaf.version>3.1.5.RELEASE</thymeleaf.version>` to root
      `pom.xml` properties. **Correction:** the property for the security-extras artifact is
      `<thymeleaf-extras-springsecurity.version>` (no "5" suffix) — verified directly against
      `spring-boot-dependencies:2.7.18`'s BOM in the local `.m2` cache; the plan's original name
      (`thymeleaf-extras-springsecurity5.version`) doesn't match anything the BOM reads and
      would have silently left the dependency pinned at Boot's default 3.0.5.RELEASE. Both
      artifacts confirmed resolving to 3.1.5.RELEASE via `mvn dependency:tree`.
- [x] Audit all `.html` templates for usage of `#request`, `#response`, `#session`,
      `#servletContext`, `#httpServletRequest`, `#httpSession` — one real hit found and fixed
      (`rules/designer.html`, see Tier 3a section above for detail). Re-swept after the fix:
      zero remaining hits across both template directories.
- [x] Verify H2 2.x test DB compatibility post-Boot upgrade — no H2/SQL failures surfaced by
      this tier's changes
- [x] Run `mvn test` — 907/907 passing, 0 failures, 0 errors, all 12 modules, BUILD SUCCESS
- [x] Perform full manual smoke test of web UI — done 2026-08-30 by the user against the
      deployed dev cluster: rule designer pages render correctly, active-tab highlighting
      confirmed working

### Tier 4 — Planned (Separate Sprints)

- [x] PMD 6.36.0 → 7.x: **Complete 2026-08-30.** Fixture-based violation test added and green
      against 6.36.0 *before* any code changed, then used as the pass/fail gate through the
      whole migration — still green after. All four anticipated rewrites done (scanner, renderer,
      designer's XPath execution, designer's AST parsing) plus two more found only by testing
      (`RuleBuilder` removal needing a special case for `XPathRule`'s new constructor;
      `AbstractRule`'s default target selector not targeting root). Flyway data migration for
      stale `rule_class` values done (`watchtower-module-pmd/db/pmd/V003`, its own per-module
      migration history — not `watchtower-core`'s). Full reactor `mvn test`: 913/913, 0
      failures, 0 errors, all 12 modules. See Tier 4a above for full detail, and its "Still
      unverified, honestly" section for what still needs a real database/browser to confirm.
- [x] Luxon 1.26.0 → 3.x: **Complete and verified** — see Tier 4b above. Only 3 files touched,
      no JS code changes needed (the codebase never used the renamed `DateTime.local()` API).
- [x] CodeMirror 5.60.0 → 6.x: **Complete and verified 2026-08-30.** Built a local esbuild
      bundle (compat shim over real `@codemirror/*` packages) instead of touching any of the 5
      designer JS files — see Tier 4c above for full detail. Automated jsdom smoke test passes;
      full reactor `mvn test` 912/912. Manually verified in-browser against the deployed dev
      cluster: PMD/ESLint/JSON/Regex designers all render and save correctly, including
      ESLint's read-only fields, JS/JSON syntax highlighting, and the modal `.refresh()`
      behavior. A Regex rule was saved end-to-end through the UI and persisted correctly.

### Tier 5 — Future Major Sprint (retargeted 2026-08-27: Spring Boot 3.x → 4.x, see tier notes above)

**Execution split into slices (2026-08-31), to isolate JDK problems from Spring Boot problems:**
Slice 1 = Java 8 → 17 while still on Spring Boot 2.7.18 (a real supported combo — Boot
2.7/Framework 5.3/Hibernate 5.6 all support 17). Slice 2 = Spring Boot 4.x + `javax`→`jakarta`
together, atomically (jakarta imports don't compile against Boot 2.7; Boot 4 doesn't compile
against javax — these two cannot be split). Slice 3 = whatever Hibernate 7/Flyway 12/JUnit
6/Mockito 5 fallout surfaces once it compiles, plus the JDK 17 → 21/25 bump this tier's own
prerequisite list calls for (deferred to Slice 3 deliberately: Spring Framework 7.0, bundled by
Boot 4.1, is what actually recommends 21/25 over 17 — no need to make that jump before Boot 4 is
in place).

- [x] **Slice 1 complete, 2026-08-31 (commit `28b6573`).** Java 8 → 17, Spring Boot left at
      2.7.18. `java.version`/`maven.compiler.source`/`target` bumped to 17 across the root pom
      and all 11 module poms. Verified 913/913 tests, 0 failures/errors, all 12 modules — both
      natively (JDK 17 on the dev machine) and via a full Docker build on the new base image
      (compile, test, package, plus a runtime `java -version`/jar sanity check).
    - **Real JDK 17 break found (not a hypothetical):** `ImageScanRestControllerTest` mocked
      `ApiType`, a 2-constant enum with one constant-specific body
      (`BITBUCKET_CLOUD { @Override ... }`). Confirmed via `javap -v` that javac 17 compiles any
      enum with a constant-specific body with a `PermittedSubclasses` attribute listing its
      anonymous constant classes — making the enum JVM-sealed even though the source never uses
      the `sealed` keyword. This is enforced by the classfile verifier itself, so no Mockito/
      ByteBuddy version can subclass it (confirmed: bumping Mockito 4.5.1 → 4.11.0 did not fix
      it — same "Cannot mock/spy ... sealed class" error either way). Fixed the test itself,
      using the real `ApiType.BITBUCKET_CLOUD` constant instead of mocking the enum, rather than
      reaching for Mockito's inline mock maker (a mock-maker switch would change final/static
      mocking behavior project-wide across all 913 tests — correctly a Slice 3 concern if Boot
      4/Mockito 5 forces it, not something to take on speculatively here).
    - **Dockerfile base image:** swapped `adoptopenjdk/openjdk8:ubi-slim` →
      `registry.access.redhat.com/ubi8/ubi` + `dnf install java-17-openjdk-devel`. **UBI9 was
      tried first and rejected**: neither Eclipse Temurin's nor Red Hat's own prebuilt JDK 17 UBI9
      images ship full `dnf`/module-stream support (only `microdnf`, no `dnf module`), and
      plain `registry.access.redhat.com/ubi9/ubi`'s AppStream repo doesn't carry the `python38`
      package this project depends on (RHEL9 dropped that SCL-style naming). UBI8 has both
      `java-17-openjdk-devel` and `python38` together, confirmed by actually installing both in
      a container — kept the Dockerfile's existing `dnf`/`dnf module install nodejs:16` structure
      unchanged.
    - No CI workflow files exist in this repo to update (no `.github/workflows`, no
      `Jenkinsfile`, no `bitbucket-pipelines.yml` found).
- [x] **Slice 3 complete, 2026-09-03 (commits `91cd08a`, `0349a38`).** Java 17 → 21 (java.version
      chosen over 25 by user decision: already installed locally, UBI8's dnf AppStream repo
      confirmed via `docker run` to carry `java-21-openjdk-devel`, Java 25 support on RHEL8's
      module streams unverified). Bumped `java.version`/`maven.compiler.source`/
      `maven.compiler.target` across the root pom and all 11 module poms, plus the Dockerfile's
      base-image JDK. Verified: full reactor test run under JDK 21, **917/917 tests passing, all
      12 modules** — exact match to the Slice 2 baseline.
    - **Prerequisite checks done before the bump:** grepped for `Thread.suspend`/`resume`/`stop`
      (removed/restricted since JDK 20) — clean, `PauseableThreadPoolTaskExecutor`'s
      `resume()`/`pause()` are custom queue-lock methods, unrelated to the deprecated `Thread`
      API. Grepped for classes implementing `List`/`Deque`/`SequencedCollection` that could
      clash with JDK 21's new default `getFirst()`/`getLast()` (JEP 431) — none found.
    - **One real break found by compiling, not by reading migration guides:**
      `maven-plugin-plugin:3.6.1`'s bundled ASM can't parse Java 21 classfiles ("Unsupported
      class file major version 65"), failing `watchtower-upload-scan`'s `descriptor` goal.
      Bumped `maven-plugin-plugin` and its paired `maven-plugin-annotations` from 3.6.1 to
      3.15.2 (latest stable; confirmed resolvable via `dependency:get` before use).
    - **Hibernate 7.x JPQL/HQL audit closed at parse level (`0349a38`):** see the item below —
      this was Slice 3's other open item, not folded into the JDK bump commit.
    - **Not yet done:** same Docker build + manual smoke test verification deferred from Slice 2,
      now also covering Slice 3's base-image change — tracked in `MANUAL_VERIFICATION.md`.
- [x] **Slice 2 complete, 2026-09-02 (commits `cf87a55`, `c7c2663`, `0607d77`, `321c12f`,
      `2c8ddb6`).** Spring Boot 2.7.18 → 4.1.1, `javax` → `jakarta` throughout, Spring Security
      rewritten to the `SecurityFilterChain` bean pattern, Thymeleaf security extras
      `springsecurity5` → `springsecurity6`, `HandlerInterceptorAdapter` → `HandlerInterceptor`.
      Verified: full reactor test run, **917/917 tests passing, 0 failures, 0 errors, all 12
      modules** — matching (and slightly exceeding) the Slice 1 baseline of 913/913.
    - **Trailing-slash redirects 404 under Boot 4 (`0607d77`):** Spring Framework 6+'s
      `PathPatternParser` (default request mapping since Boot 3) stopped treating a trailing
      slash as equivalent to the mapped path. `RulesetsController.makeRedirect(id)` and
      `PullRequestMCRReportController`'s "unknown ID" fallback both built redirect targets with
      a stray trailing slash and nothing after it — breaking every redirect the former emits
      (create, edit, delete, set-default, import) in production, not just in tests. `rulesets.js`
      had the identical client-side bug in its ruleset-picker's `change` handler. All three fixed
      by dropping the trailing slash to match the real mapping.
    - **Null-guard gap in `ImageScanResult` (`321c12f`):** `getSubmitDateMillis()` /
      `getEndDateMillis()` dereferenced their backing `LocalDateTime` fields unconditionally,
      NPEing during Jackson REST serialization for any scan without an end date yet (i.e. still
      in progress). Sibling DTO `UploadScanResult` already null-guards the same pattern; applied
      the same fix here.
    - **Module plugins silently stopped registering (`2c8ddb6`) — the big one.** Each of the six
      scan modules (ESLint, PMD, Regex, JSON, Checkov, Advisory) registers its
      `@WatchtowerModule`-annotated class via the legacy
      `META-INF/spring.factories` `EnableAutoConfiguration` key. **Spring Boot 3.0 removed
      support for that key entirely** (replaced by
      `META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports`) —
      since this migration jumped straight from 2.7.18 to 4.1.1, none of these modules were
      being registered at all under Boot 4. This was not a test-only issue: none of their
      controllers, repositories, or entities were ever scanned into the Spring context in
      production either. Migrated all six to `AutoConfiguration.imports`. Fixing registration
      surfaced a second gap: `AbstractModule`'s `@Autowired Flyway` field had no bean to inject
      anywhere, because Boot 4 also split `FlywayAutoConfiguration` out of the monolithic
      `spring-boot-autoconfigure` jar into its own `spring-boot-flyway` module — added that
      dependency to `watchtower-core/pom.xml` (propagates transitively to every module). Without
      both fixes, each module's per-module Flyway migrations (own schema history table, own
      `migrations/` folder) would never have run in the real app either.
    - **Not yet done:** a Docker build verification matching how Slice 1 was verified (`mvn test`
      alone doesn't run `package`, and doesn't catch `watchtower-upload-scan`'s maven-plugin
      packaging or `watchtower-web`'s frontend/packaging steps) — tracked in
      `MANUAL_VERIFICATION.md`.
- [x] Upgrade Spring Boot parent to 4.x (verified latest at drafting: 4.1.1 — re-check at
      execution time) — done above (Slice 2)
- [x] Execute `javax.*` → `jakarta.*` rename across all source files — done above (Slice 2)
- [x] Rewrite Spring Security config from `WebSecurityConfigurerAdapter` to `SecurityFilterChain` bean — done above (Slice 2)
- [x] Update Thymeleaf security extras: `springsecurity5` → `springsecurity6` (3.1.5.RELEASE) —
      confirmed no `springsecurity7` artifact exists; `springsecurity6` is correct for Security 7.x too — done above (Slice 2)
- [x] Fix Hibernate 7.x JPQL/HQL compatibility issues (two majors' worth of change from the
      current 5.6.x, not one) — **parse-level compatibility verified, 2026-09-03 (commit
      `0349a38`).** A green suite alone doesn't prove this (see the note this line replaced), so
      the audit grepped for every hand-written query surface: `@Query`, `createQuery`,
      `createNativeQuery`, `@NamedQuery`, `nativeQuery = true`, direct `EntityManager` usage,
      Criteria API. Found exactly 5 hand-written JPQL queries across 4 repositories (no native
      queries, no Criteria API). Further found that **zero tests in this codebase exercise a
      real, non-mocked Spring Data repository** — every test touching these repositories uses
      `@MockitoBean`, which intercepts calls before they reach Hibernate's parser. So none of
      the 5 queries had ever been parsed by any Hibernate version, not just 7.x. Added one
      minimal test per query (`PRScanRepositoryTest`, `PRViolationRepositoryTest`,
      `UploadViolationRepositoryTest`, `ImageViolationRepositoryTest`), autowiring the real
      repository against the Flyway-provisioned H2 test DB rather than mocking it — an empty
      table is sufficient, since a parse failure throws regardless of row count. All 5 parse and
      execute cleanly under Hibernate 7.4.5, including `PRScanRepository`'s two queries (a
      correlated `EXISTS` subquery whose `HAVING` references the outer alias, and a `countQuery`
      selecting an entity from inside `EXISTS(...)`), the shape most likely to trip Hibernate 6's
      ANTLR-based HQL parser rewrite. **Scope note: this verifies the queries parse and execute,
      not that they return correct results against real data** — `HAVING`-with-outer-alias
      result-correctness against a populated dataset is a real-database concern, tracked
      alongside the Flyway real-DB item in `MANUAL_VERIFICATION.md`.
- [ ] Re-run `mvn flyway:validate` against the Flyway 8.x → 12.x jump — `migrate` runs clean on
      every test boot, but that's H2 in-memory from an empty baseline (no existing schema
      history, so no checksums to check) — the opposite of what `validate` actually tests.
      Standalone `validate` against a real database with existing migration history not yet run;
      see `MANUAL_VERIFICATION.md`'s real-database Flyway item.
- [ ] Run full test suite and smoke tests — test suite done (Slice 2, above); smoke tests still
      open, see `MANUAL_VERIFICATION.md`
- [x] Check `HandlerInterceptorAdapter` usage in `WatchtowerMvcHandler` — replace with `HandlerInterceptor` interface — done above (Slice 2)
- [x] Cross-check the official [Spring Boot 4.0 Migration Guide](https://github.com/spring-projects/spring-boot/wiki/Spring-Boot-4.0-Migration-Guide) for anything not captured above —
      **done, 2026-09-03.** Fetched all 55 listed breaking changes and checked each against this
      codebase. Two worth recording (both confirmed safe, no action needed):
    - **Jackson 2 and Jackson 3 coexist on the classpath.** `spring-boot-starter-web` transitively
      pulls Boot 4.1's own `spring-boot-starter-jackson`, which brings in Jackson 3
      (`tools.jackson.core:jackson-databind:3.1.5`) for Spring's own MVC/REST serialization.
      Meanwhile 12 files in this codebase's own production code still import
      `com.fasterxml.jackson.*` (Jackson 2, `2.21.5` — also pulled in transitively via the AWS
      SDK). Checked each: all are self-contained (manually-constructed `ObjectMapper`/`JsonMapper`
      instances in `RulesetService`/`JsonCallable`, `@JsonIgnore` annotations, exception types) —
      **zero `@Autowired ObjectMapper` anywhere**, so nothing depends on Spring auto-wiring a
      Jackson-flavored bean. No conflict; confirmed working by the full green test suite,
      including `RulesetsControllerTest`'s JSON import/export flow.
    - **Flyway wired via the raw `spring-boot-flyway` module (`2c8ddb6`), not the
      `spring-boot-starter-flyway` aggregator the guide names.** Checked the starter's own POM:
      it only adds `spring-boot-starter-jdbc` on top of the same `spring-boot-flyway` module —
      already present transitively here via `spring-boot-starter-data-jpa`. Functionally
      equivalent for this project; not a gap.
    - Everything else in the 55-item list is either already handled by Slice 2/3 (Jackson
      component renames not applicable since this codebase never used `@JsonComponent`;
      `@EntityScan` relocation; `@MockBean`→`@MockitoBean`; `@AutoConfigureMockMvc`) or
      confirmed not applicable to this stack (no MongoDB, Kafka, AMQP, Elasticsearch, Spring
      Batch, Undertow, Pulsar, Spock, DevTools, Spring Session, WAR packaging, or Gradle
      anywhere in the reactor).

---

## 6. Security Issues NOT Covered by Upgrades

The following issues require code changes and are not resolved by any dependency upgrade. They should be tracked separately and prioritized for dedicated fixes.

---

### 6a. Unbounded Thread Pool Queue (OOM Risk)

**Location:** `PauseableThreadPoolTaskExecutor`  
**Issue:** The internal work queue is a `LinkedBlockingQueue` with no capacity limit. Under a webhook flood (many simultaneous POST `/rest/scan/{source}` requests), the queue can grow unbounded and cause an `OutOfMemoryError`.  
**Fix:** Construct the `LinkedBlockingQueue` with an explicit capacity (e.g., 500 or 1000) and define a `RejectedExecutionHandler` to handle queue-full situations gracefully (e.g., log and return HTTP 429).

---

### 6b. No HMAC/Signature Verification on Scan Webhook Endpoint

**Location:** `POST /rest/scan/{source}`  
**Issue:** Any caller that can reach the endpoint can trigger a scan or flood the queue. There is no signature verification (e.g., GitHub webhook HMAC-SHA256 shared secret validation) to ensure the request actually originated from the expected source.  
**Fix:** Implement per-source HMAC signature verification, rejecting requests that do not present a valid `X-Hub-Signature-256` (or equivalent) header.

---

### 6c. Silent HTTP 200 When Scan Is Dropped

**Location:** Scan ingestion flow  
**Issue:** When a scan is silently dropped (because no ruleset is configured or no scanners match the source), the API returns HTTP 200 OK. The caller receives no indication that nothing happened. This makes webhook integration unreliable and difficult to debug.  
**Fix:** Return HTTP 202 Accepted when a scan is queued, HTTP 204 or a distinct error code (e.g., 422 Unprocessable Entity) when a scan is dropped, with a clear reason in the response body.

---

### 6d. NPE Risk in PRScanningService

**Location:** `PRScanningService`, lines 94–95  
**Issue:** The code calls `findByLabel()` a second time without a null check on the result. If the label is not found on the second call, a `NullPointerException` will be thrown.  
**Fix:** Add a null check after the second `findByLabel()` call and handle the missing-label case with a clear log message and appropriate fallback behavior.

---

### 6e. Raw Exception Messages Returned to Unauthenticated Callers

**Location:** `PRScanRestController`  
**Issue:** Exception stack traces or raw exception messages may be included in HTTP error responses returned to callers who are not authenticated. This leaks internal implementation details (class names, file paths, SQL structure) that aid attackers.  
**Fix:** Implement a `@ControllerAdvice` / `@ExceptionHandler` that catches all unhandled exceptions in REST controllers and returns a generic, non-revealing error message for unauthenticated callers. Log the full exception server-side only.

---

### 6f. H2 Web Console Exposed to All Hosts

**Location:** `application.yaml` (dev/test configuration)  
**Issue:** H2's web console is enabled with `spring.h2.console.settings.web-allow-others=true`, which allows connections from any network host — not just localhost.  
**Fix:** Set `spring.h2.console.enabled=false` in any configuration that could be deployed outside a developer's own machine. If the console is needed for local development, ensure it is only enabled via a profile (`spring.profiles.active=local`) that is never active in staging or production environments.

---

## 7. Testing Strategy

### Baseline — ✅ Established and clean (2026-08-27)

The original baseline run surfaced 112 failing/erroring tests across the reactor. All were
triaged and fixed across three commits (`949c459`, `27a71ff`, plus the initial Tier 1 bump in
`4a8ddd9`); the current baseline is **907/907 tests passing, 0 failures, 0 errors, all 12
modules**. Root causes, for reference when regressions do appear during Tiers 2–5:

| Root cause | Tests affected | Where |
|---|---|---|
| `ScannerModuleTest` compared a bare `Class` against the real scanner's `List<Class<...>>` | 9 | `watchtower-test` + 5 scanner modules |
| `v.getSeverity().equals(RulePriority.INFORMATIONAL)` NPEs on null severity, silently swallowed by `MetricsCacheService`'s catch-all | 13 | 3 chart generators + `MetricsCacheServiceTest` |
| `RulePriorityTest` used `6` as an "invalid" priority — it's `INFORMATIONAL`'s own valid value | 1 | `watchtower-core` |
| Two Mockito stubs for `getSupportedRuleClass()` returned a bare `Class` instead of `List` | 2 | `AbstractScanAgentTest` |
| `EcrApi`'s constructor made a live, unmockable AWS call using literal fake test credentials | 17 | `EcrApiTest` |
| `ApiIntegrationServiceTest.testRegisterFailure` didn't await its async `CompletableFuture`, racing the verify() calls | 1 | `watchtower-core` |
| `linter_parse.js`'s `getCoreCategories()` returned a raw JS value instead of `JSON.stringify()`-ing it, breaking Gson parsing on the Java side; silently swallowed during Spring context startup | 36 | `watchtower-module-eslint` + `watchtower-web` |
| Same `List` vs `Class` bug as above, in the eslint module specifically (masked until the JSON bug above was fixed) | 2 | `watchtower-module-eslint` |

Re-establish this baseline (`mvn test`, full reactor) before starting each subsequent tier, and
compare against it — not against "all green," in case new pre-existing issues surface.

```bash
mvn test 2>&1 | tail -20
```

---

### Tier 1 Testing

After each individual library upgrade, run the module most likely to exercise that library:

```bash
# org.json
mvn test -pl watchtower-module-json

# commons-lang3, commons-io, zip4j
mvn test -pl watchtower-core

# Full regression after all Tier 1 changes
mvn test
```

---

### Tier 2 Testing

```bash
# Full test suite — must pass before proceeding
mvn test

# Flyway migration checksum validation (critical before any deploy)
mvn flyway:validate -pl watchtower-web

# Full build including integration tests
mvn verify

# Check for H2 2.x keyword conflicts in test output
mvn test 2>&1 | grep -i "JdbcSQLSyntaxError\|SchemaObjectNotFound\|keyword"
```

---

### Tier 3 Testing

```bash
# Unit tests
mvn test

# Then perform a manual smoke test of every page in the web UI:
```

**Manual smoke test checklist:**

- [ ] Login page renders and authentication works
- [ ] Dashboard loads with correct sidebar (verify sidebar pre-filtering still works)
- [ ] PR scan webhook accepts and queues a request
- [ ] Upload scan flow completes end-to-end
- [ ] Scan results page displays findings correctly
- [ ] Admin panel loads (users, roles, configuration)
- [ ] Rule management page: create, edit, delete a rule
- [ ] Code editor (CodeMirror) renders in rule editing view
- [ ] Date/time displays (Luxon) render correctly on scan history views

---

### Tier 4 Testing

Each Tier 4 item has module-specific tests:

```bash
# PMD module
mvn test -pl watchtower-module-pmd

# Full regression
mvn test
```

For Luxon and CodeMirror, automated testing is limited to what Spring MVC tests cover. The primary verification is manual UI testing of all pages that use date display or code editing.

---

### Tier 5 Testing

After the Java 17+ + Spring Boot 4.x migration:

```bash
# Verify compilation succeeds (javax → jakarta rename complete)
mvn compile

# Full test suite
mvn test

# Flyway validation — re-run against the 8.x → 12.x jump, not just re-checking Tier 2's result
mvn flyway:validate -pl watchtower-web

# Full build
mvn verify
```

**Manual smoke test:** Run the complete checklist from Tier 3, plus verify all security-sensitive flows (login, logout, session expiry, access control on admin endpoints) work correctly under the Spring Security 7 configuration.

---

*This document is the single source of truth for the Watchtower dependency upgrade plan. Update the Progress Tracker section as items are completed.*
