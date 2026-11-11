# Manual Verification Checklist

Tracks manual (browser / live-database / live-cluster) checks that this environment cannot
perform itself, split out from `UPGRADE_PLAN.md` so they can be tested independently of
whatever upgrade tier is being worked on next. Check items off as they're confirmed; if
something breaks, note it inline rather than deleting the line, so there's a record of what
regressed and when.

---

## Outstanding — Tier 4a (PMD 6 → 7), not yet checked

- [ ] Run a real scan (PR or upload) through a ruleset containing at least one **provided**
      rule and one **custom** (XPath) rule. Confirm violations are actually detected — a
      migration that silently returns zero violations would look identical to a healthy one
      without this check.
- [ ] Open the **PMD Rule Designer** in a browser. Confirm the AST view renders for a sample
      snippet and that XPath match-testing still returns results.
- [ ] Confirm Flyway migration `V003__Fix_Stale_PMD_XPathRule_Class.sql`
      (`watchtower-module-pmd/src/main/resources/db/pmd/`) actually ran against the real
      database and rewrote any `pmd_rules.rule_class` rows that still had the old
      `net.sourceforge.pmd.lang.rule.XPathRule` (pre-move) class name.
- [ ] Query the real `pmd_rules` table for provided-rule names and cross-check them against
      PMD 7.27.0's actual rule catalog. This can't be fixed in code — `PMDRuleService` resolves
      provided rules by name against whatever PMD 7 ships, live, at scan time. A renamed or
      removed rule name fails with `RuleNotFoundException` only when a scan actually uses it,
      not at boot.
- [ ] (Lower priority, dormant feature) If `BasicPomRule`'s `RESOLVE_PROPERTIES` /
      `${project.x.y}` property-resolution is ever turned on for a real rule, verify it
      manually — the Jaxen → `javax.xml.xpath` port preserved the same query string but wasn't
      exercised by any test.
- [ ] (Lower priority) Check the real `pmd_properties` table for `|`-delimited values on any
      list-typed custom PMD rule property (e.g. `RestrictNodesUnderProject`'s `subNodes`, if
      ever configured outside the UI). PMD 7 changed the multi-value delimiter from `|` to `,`.

## Outstanding — Tier 5 Slice 2 (Spring Boot 4.1.1), not yet checked

- [x] **Full local Docker build verification — done, 2026-09-04 (commit `526bcaf`).** Base image
      switched from Red Hat UBI8 to `eclipse-temurin:21-jdk-jammy` (Eclipse Foundation, Ubuntu
      22.04 — see that commit for the full rationale). Actually built and ran the image locally,
      not just planned it: `./mvnw clean package` succeeded inside the container (922/922 tests,
      all 12 modules), `java -version` confirmed Temurin 21.0.12 LTS, `checkov`/`node`/`eslint`
      all resolve correctly, and the real jar reaches Spring context initialization (fails only
      on the expected missing prod datasource config in a throwaway container — correct
      behavior). Three real Debian-vs-RHEL platform bugs found and fixed in the process
      (`ensurepip` disabled on Debian, `useradd` needing `-m` for a home dir, an `ENV` variable
      same-instruction resolution bug) — see the commit message for details.
      **Still needs your hands:** the actual dev-cluster deploy and a real smoke test against
      real infrastructure (secrets, real datasource, real ingress) — this only proves the image
      builds and boots correctly in isolation, not that it works end-to-end in your environment.
- [ ] Manual smoke test in a browser: rulesets page navigation, create/edit/delete/import a
      ruleset, and the Manual Code Review report flow — the trailing-slash redirect bug fixed in
      `0607d77` was a real production 404 on every one of these flows under Boot 4, not just a
      test artifact; worth confirming visually now that it's fixed.
      **Partially done 2026-09-04:** the Manual Code Review report flow (labels + status filter)
      is confirmed working against the real dev DB. Rulesets page navigation and ruleset
      create/edit/delete/import are still unconfirmed.
- [ ] Confirm each scan module's Flyway migrations actually apply against a real (non-H2)
      database on first boot under Boot 4.1.1 — `2c8ddb6` fixed a bug where none of the six scan
      modules (ESLint, PMD, Regex, JSON, Checkov, Advisory) were being registered as Spring beans
      at all, meaning their per-module migrations never ran. Confirmed via H2 in tests; not yet
      confirmed against dev/prod's real database.

## Outstanding — Tier 5 Slice 3 (Java 21 + Hibernate 7 audit), not yet checked

- [x] **`PRScanRepository.findLatestMcrsPerPRByMcrStatus` / `findLatestMcrsPerPR` result
      correctness — verified 2026-09-04, real dev DB.** Manually filtered PRs by MCR status
      (Pending Review / In Progress / Reviewed / Reviewed w/ Recommendations) on the live
      `/pullrequests/mcrs` report page against real, populated data — confirmed the correlated
      `HAVING p.submitDate = MAX(p2.submitDate)` subquery still returns the correct latest-scan-
      per-container rows under Hibernate 7.4.5, closing the result-level gap `0349a38`'s
      parse-only H2 test left open. (Same session also fixed a real bug found via the dev
      deployment: `PullRequestScanEntity.mcrStatus` had no `@Enumerated`/`@Convert`, so Hibernate
      7's changed ordinal-enum JDBC type default was misreading the `VARCHAR` `mcr_status`
      column — see git history for the `PullRequestMCRStatusConverter` fix.)

## Outstanding — general

- [ ] Deploy Tiers 1–4 to **prod** (dev is verified as of 2026-08-30; prod hasn't been
      touched). Same `--dry-run` → deploy → spot-check pattern as dev.
- [ ] Prod's `mvn flyway:validate` / checksum integrity — dev was confirmed via a clean boot
      (Spring Boot runs Flyway `migrate` + `validateOnMigrate` at startup), but that doesn't
      cover prod's database.
- [ ] Rotate the `Watchtower1!` password that was hardcoded in `application-prdtest.yaml`'s
      git history before this round of work — confirm it's no longer valid on the real RDS
      instance if it hasn't been rotated already.

## Outstanding — Scan infrastructure (IMPROVEMENT_PLAN Phases 1 & 5), deploy `07c85ea`

19 plan items landed in 26 commits. Most are covered by the 768-test suite; this section
lists only what a live deploy can tell us that the suite cannot. Work top to bottom — the
setup steps gate several later checks, and a handful of actions cover most items.

### Setup, in this order

- [ ] Deploy **`07c85ea`**, not `63922eb`. The older SHA lacks the results-page fix
      (`351048d`) and will still time out.
- [ ] Confirm Flyway applied **V032** (`webhook_secret` on `bb_cloud_integration_entity`).
      A failed migration stops the pod from starting, so a healthy pod is the check.
- [ ] `kubectl describe pod <pod> -n watchtower | grep -A6 -i limits` — confirm
      **`ephemeral-storage` 2Gi request / 8Gi limit** is present. Verifies items 1.1/1.2, and
      specifically that `deploy.sh` did *not* strip them (it reuses cpu/memory from the live
      deployment but not ephemeral-storage).
- [x] Generate a random secret. Set it in **Bitbucket first**, then in Watchtower →
      API settings → the Bitbucket integration → **Webhook Secret**. Reversing the order
      401s every delivery. While unset, expect
      `No webhook secret configured for api label ...; accepting the delivery unverified`
      on each webhook — that line vanishing is how you know 1.9 is live. Confirmed live
      2026-09-11 alongside 1.9.
- [ ] In the Bitbucket webhook config, subscribe to **`pullrequest:fulfilled`** and
      **`pullrequest:rejected`** as well as created/updated. Item 5.1 is otherwise never
      exercised.

### One PR scan covers eight items

Push a branch and open a PR against a repo that has a ruleset. Then check the log for one
scan:

- [x] **1.12** — confirmed 2026-09-11, wt-test-48: `Downloaded source for wt-test-48 in 1
      attempt(s), 28789 bytes`. One attempt.
- [x] **1.0 + 1.3** — confirmed 2026-09-11, wt-test-48: `Violation classification for
      wt-test-48: 24 file(s) with violations, 1 of them changed in this Pull Request; 6
      violation(s) kept (0 new, 6 pre-existing), 411 dropped as not in the diff, 1 MCR dropped
      outside +/-5 lines, 0 diff fetch failure(s)`. Plausible split, not all-dropped.
- [x] **1.3** (at DEBUG) — confirmed 2026-09-11: diff fetches logged in the hundreds of bytes
      (e.g. 801 bytes for `ImageSecurityReport.java`), several 0-byte/no-change diffs — not
      whole file bodies.
- [x] **1.4 + 1.5** — confirmed 2026-09-11: exactly one `Requesting PR data for wt-test-48`
      line for the whole scan, no second call later in the log.
- [ ] **1.8** — still open. wt-test-48 only touched `.java`/`pom.xml` files, so this hasn't
      been exercised yet — needs a PR that actually includes a binary file (a `.class`, or a
      `.png` renamed to `.txt`). Confirm no violations are reported against it and no scanner
      errors mention it. (Note: this same scan logged unrelated `Parsing error: Unexpected
      token com` / `Unexpected character '#'` lines from JSON/Regex-type rules choking on
      `.java` source — that looks like pre-existing cross-scanner noise, not new breakage, but
      worth a second look if 1.8 turns up something similar for an actual binary.)
- [x] **1.10** — confirmed 2026-09-11 in Bitbucket's webhook delivery log: **202** for
      wt-test-48's delivery, **422** for a repo with no ruleset.
- [x] **8c6db86** (at DEBUG) — confirmed 2026-09-11: `Promoting extracted root
      '<workspace>-<repo>-<commit>' to the working directory for
      wt-test-48`.

### Then merge that PR

- [ ] **5.0 + 5.1 + `17538e1`** — deferred, will be tested last. Expect
      `is already MERGED; resolving without scanning`, and crucially **no** `Downloaded source`
      line for it. This is the check that failed on 2026-09-05: a merged PR was scanned in full
      and then had a decline attempted against it, producing `Bad response: 400 while declining
      PR`. That error must not appear.

### Deduplication

- [ ] **1.7** — attempted 2026-09-11, did not reproduce the expected dedup behavior on two
      tries (no `an identical scan is already in flight for commit <hash>` line seen). Not
      diagnosing now — retest later.

### First synchronizer pass (runs ~1 min after startup, then every 3h)

- [x] **5.3** — tested 2026-09-11. Not digging further: the synchronizer is slated to change,
      so re-verifying its current behavior in detail isn't worth it — re-test against the new
      implementation once that lands instead of this one.

### Results page

- [x] **504 fix (`351048d`)** — confirmed 2026-09-11: `/scan/results/all` no longer 504s, but
      still loads very slowly.
      **Root cause found and fixed the same day:** the 10-row-per-page pagination on
      `/scan/results/all`, `/scan/results/violations`, and all the `/scan/mcr/*` views was
      already real (DB-level `LIMIT`), so "fetch less data" wasn't the gap. The actual cost was
      the *count* query each `Page<>` return type triggers: `findLatestMcrsPerPRByMcrStatus`
      and `findLatestMcrsPerPR` had a hand-written `countQuery` that re-runs the same per-row
      correlated `EXISTS` subquery (nested inside another `EXISTS`) across the *entire* table to
      report an exact total, and `findAllNonMCRGroupByScan`'s implicit count query does the
      same for its `GROUP BY`. None of that total is ever shown — `pull_requests/mcrs.html` and
      `results.html` only render `Page: N` with Previous/Next. Switched all three repository
      methods (`PRScanRepository`, `PRViolationRepository`) from `Page` to `Slice`, which drops
      the count query entirely and only fetches pageSize+1 rows. `PRScanResultService`'s callers
      needed no change (`.stream()` works identically on `Slice`). Updated the 3 tests that
      referenced the old `Page` return type; `PRScanRepositoryTest`/`PRViolationRepositoryTest`/
      `PRScanResultServiceTest` pass under JDK 21.
      **Still needs your hands:** deploy and re-open `/scan/results/all`, `/scan/results/
      violations`, and the MCR views against the real dev DB to confirm the actual latency drop
      — this was diagnosed from the query shape and the templates, not measured against
      production-sized data.
- [ ] (Optional, out of scope for this fix) The "Next" link on both pages is never disabled at
      the last page, unlike "Previous" at page 0. `Slice.hasNext()` would make that fixable
      cheaply now, but wiring it through the service/controller/template is a separate, larger
      change — not done here.

### Webhook signature, negative test

- [x] **1.9** — confirmed 2026-09-11. Mismatch (401) was observed live throughout the
      secret-mismatch investigation (`04666ee`–`d8908c8`) before the real-world secret was
      corrected, and a genuine Bitbucket delivery now succeeds. Treating the mismatch case as
      covered by that indirect evidence rather than re-running the `sha256=deadbeef` curl by
      hand.

### Lower priority / harder to stage

- [ ] **1.6** (bounded queue) — needs ~100+ concurrent submissions to reach the cap. Not
      worth staging deliberately; if it ever triggers you will see
      `Scan queue is full (capacity 100, active N)` and the webhook gets a 503.
- [ ] **1.14** (upload recovery) — needs `watchtower.runAfterStartup=true` plus an upload
      pending at restart. **Note the cost:** that flag also re-enables PR startup recovery,
      which polls Bitbucket for every open PR in every repo. Not advisable on a shared
      cluster purely to test uploads.
- [ ] **06a633d** (deletion-only files still report violations) — needs a PR whose only
      change to a file is deleted lines, where that file also has an existing violation.
      Worth constructing once, since the failure mode is silent: violations vanish.

### Covered by the test suite — no manual check needed

1.13 (MCR behaviour pinned by 6 characterization tests, no runtime change), the
`WebhookSignatures` HMAC vectors, `FileTypeUtils` binary detection, `DiffFile` hunk-header
parsing including the context=0/context=100000 equivalence gate, the thread-pool capacity
and rejection behaviour, and the per-distinct-rule query count on the results page.

---

## Already verified (2026-08-30, dev cluster) — for reference, not re-testing

- [x] Version badge shows the real deployed image tag in the page corner.
- [x] Tier 3 (Thymeleaf 3.1.5): rule designer active-tab highlighting renders correctly.
- [x] Tier 4b (Luxon 3.7.2): date/time displays render correctly.
- [x] Tier 4c (CodeMirror 6): PMD/ESLint/JSON/Regex rule designers all render and save
      correctly, including ESLint's read-only fields, JS/JSON syntax highlighting, and the
      modal `.refresh()` behavior. A Regex rule was saved end-to-end through the UI.

## Housekeeping (not a test, but tracked here to avoid losing track of it)

- [ ] Merge `release-2026.1.0` into `master` — 16+ commits have landed on this branch since it
      diverged; master has none of them yet.
