# Flyway migration immutability fix

## User journey

As an operator upgrading an existing Watchtower database, I want previously applied migrations to retain their recorded checksums so that the application starts and applies later changes forward-only.

## RED

`MigrationImmutabilityTest` initially reported:

- V039 expected `-1553298366`, actual `-1079580859`.
- `V042__Create_Metrics_Processed_Scan.sql` was missing.

The running database also reported V040 expected `-2103833108`, actual `1979396826`.

## GREEN

- Restored V039 checksum: `-1553298366`.
- Restored V040 checksum: `-2103833108`.
- Added V042 for `metrics_processed_scan` schema creation.
- Added V043 for processed-scan marker backfill.
- Focused regression tests: 2 passed.
- H2 integration startup successfully applied and validated all 43 migrations at schema version `043`.

## Broader verification

The core suite executed 995 tests: 994 passed. One unrelated existing test,
`BBCloudApiTest.testUpdatePRData`, failed with `NoHttpResponse` from its external HTTP target.
No Flyway or migration test failed.

## Guarantee

`MigrationImmutabilityTest` locks the production-applied V039/V040 checksums and verifies that the idempotency schema/data changes live in forward migrations instead of historical files.
