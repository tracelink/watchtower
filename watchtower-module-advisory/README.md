# Watchtower Module: Advisory

This module has rule that **allows** an advisory. Rules act as allow-lists that remove a finding from a remote image repository's Security Report mechanism.

## License

[MIT License](https://opensource.org/licenses/MIT)

## Table of Contents

- [Module Name](#module-name)
- [Database Schema History Table](#database-schema-history-table)
- [Database Migrations Location](#database-migrations-location)
- [Additional Rule Fields](#additional-rule-fields)

## Module Name

Advisory

## Database Schema History Table

`advisory_schema_history`

## Database Migrations Location

`db/advisory`

## Additional Rule Fields

None. This module uses the Rule Name field to match against CVE/RHSA/Other advisory names.
