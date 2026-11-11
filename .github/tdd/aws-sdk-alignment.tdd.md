# AWS SDK runtime alignment fix

## User journey

As a Watchtower operator, I want the deployable application to use one binary-compatible
AWS SDK release so that S3, SQS, ECR, STS, and CloudWatch clients can initialize at startup.

## RED

`./mvnw -pl watchtower-web dependency:tree -Dincludes=software.amazon.awssdk:* -Dverbose`
resolved most AWS SDK infrastructure modules to `2.46.21`, but resolved service modules and
`profiles` to `2.17.173`. The packaged application then failed with
`NoClassDefFoundError: software/amazon/awssdk/profiles/ProfileFileSupplier`.

## GREEN

- Imported the AWS SDK BOM at `2.46.21` in the parent POM.
- Removed the five per-service `2.17.173` version pins.
- Dependency verification resolves all 38 AWS SDK artifacts to `2.46.21`.
- `S3ServiceTest` and `SqsScanQueueServiceTest`: 19 tests passed.
- The `watchtower-web` reactor package build succeeded.
- The executable JAR contains `profiles`, `sdk-core`, `s3`, `sqs`, `sts`, `ecr`,
  `cloudformation`, and `cloudwatch` only at `2.46.21`.

## Guarantee

The deployable JAR no longer mixes the incompatible AWS SDK `2.17.173` and `2.46.21`
module lines that caused startup to fail.
