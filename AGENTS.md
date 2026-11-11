# Repository instructions

## UI development target

Design, implement, and visually verify Watchtower UI for desktop viewports only. Use a
1440px-wide desktop viewport as the default review target. Do not add mobile- or tablet-specific
layouts, breakpoints, or visual checks unless the user explicitly requests them. Preserve existing
responsive behavior when editing shared UI code, but do not expand mobile support as part of
desktop UI tasks.

## Database persistence

Use the existing Hibernate/Spring Data JPA stack for all application database CRUD, including
assistant, rules, feedback, metrics, jobs and repository catalog code. This rule applies to existing
code as well as new changes.

- Model application records as typed JPA entities and access them through repositories.
- Use entity operations, derived repository methods, JPQL or the JPA Criteria API. Do not use
  `JdbcTemplate`, `NamedParameterJdbcTemplate`, handwritten SQL, `createNativeQuery`, or
  `nativeQuery = true` for application data access.
- Preserve transactions, optimistic versions, pessimistic locks and conditional updates needed
  for leases, claims, budgets and idempotency. Express atomic bulk operations through JPA.
- Bind query parameters. Never concatenate user input into JPQL, identifiers or sort clauses.
- SQL is permitted in Flyway schema migrations and database test setup/assertions. Infrastructure
  SQL owned internally by third-party libraries (such as ShedLock) is outside application CRUD;
  do not copy its SQL into application services.
- Keep a regression check that prevents direct JDBC/native SQL application CRUD from returning.

## Existing work

Preserve unrelated working-tree changes. Assistant chat remains disabled by default until its
documented activation gates pass. R3 uses bounded direct engine execution by explicit user request;
sandboxing is deferred and must not be claimed as implemented.
