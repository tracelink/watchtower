# Opengrep 1.30.2 — R4

Watchtower executes a checksum-pinned standalone binary directly with local JSON rule configs.
The binary is LGPL-2.1; the bundled starter checks are original MIT Watchtower rules. Imports
must record a licensed, versioned source. No upstream catalog or remote config is fetched.

The adapter admits Python, JavaScript, TypeScript, Java and YAML. Pattern syntax and intra-file
cross-function source/sink/sanitizer flows are verified on representative fixtures. This does not
certify every construct or language version. Stable 1.30.2 is not certified for cross-file taint;
a two-file control remains unmatched. A missing match does not establish unreachability.

One definition object supplies languages and pattern or taint fields. Watchtower binds stable rule
ID, message and severity itself. Rule ID is independent of display name. Findings keep Watchtower
rule revision and priority. Errors, unsupported targets, time/output/memory limits and disabled
modules are distinct from successful execution with no findings. Native provenance is incomplete,
so Opengrep reports rescan and cannot reuse old reports.

The module starts disabled. Authorized engineers can change its shared policy through Scanner
modules. Runtime disablement preserves rules, rulesets, import/export and history; it hides the
designer and prevents tests and new shadow/promotion. Queued work rechecks current policy. Tests
and shadow use the existing human-reviewed R3 boundary; assistant tools cannot execute or approve.

Direct execution is not sandboxed. Separate Java/process deadlines and engine memory flags do not
isolate the host filesystem or network. Chat remains disabled by default. Review rules against
positive/clean regression and held-out fixtures before assigning enforcement.
