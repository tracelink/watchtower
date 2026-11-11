# Metrics dashboard ranges and PR performance

## User journeys

- A dashboard user can discover and apply a custom date range on every chart.
- A keyboard or screen-reader user can identify both date fields and their validation error.
- A completed PR scan contributes a performance sample even when its daily projection row is missing.

## Evidence

| Guarantee | Test | Result |
|---|---|---|
| All nine dashboard charts expose a visible custom-range action | `DashboardCustomDateRangeTest` | PASS |
| Generated date inputs have connected labels and an announced error | `DashboardCustomDateRangeTest` | PASS |
| A missing daily row is created during PR performance finalization | `MetricsProjectionWriterTest` | PASS |
| Custom API dates override the preset period | `MetricsRestControllerTest.customScanRangeUsesInclusiveDatesInsteadOfPreset` | PASS |

RED was captured with three expected failures before implementation: the visible actions and accessible fields were absent, and performance finalization did not insert a missing projection row.

GREEN command:

`./mvnw -pl watchtower-core -Dtest=DashboardCustomDateRangeTest,MetricsProjectionWriterTest,MetricsCacheServiceTest,MetricsRestControllerTest,PRDashboardControllerTest,PRScanResultServiceTest test`

Result: 44 tests passed with no failures or errors. The additional focused API run passed 14 tests. `node --check` and `git diff --check` also passed.

Coverage was not recalculated for the full repository. Browser interaction remains to be confirmed in the deployed dev environment. Historical scans cannot provide phase timings that were not captured; the UI now explains that a newly completed PR scan is required.
