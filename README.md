# Watchtower

![Watchtower Logo](watchtower-core/src/main/resources/static/images/watchtowerlogo.svg)  
A static code analysis and reporting server to quickly identify issues in code and display scan
results and metrics. Scans can be performed automatically by integrating with a source code
management (SCM) pull request system, or manually by uploading source code to scan as a zip file.
Collected scan data is displayed on server Dashboards.

The server can include multiple Modules to perform different types of scans. Each module defines its
own type of rules, which are then aggregated into rulesets and applied to code during a scan.

## Status

[Badges go here]

## License

[MIT License](https://opensource.org/licenses/MIT)

## Table of Contents

- [General Info](#general-info)
- [How TraceLink uses Watchtower](#how-tracelink-uses-watchtower)
- [Technologies](#technologies)
- [Installation](#installation)
- [Authentication](#authentication)
- [What is a Module](#what-is-a-module)
- [Modules Available](#modules-available)
- [Customization](#customization)
- [Contributions](#contributions)
- [Authors](#authors)
- [License](#license)

## General Info

Watchtower is a Spring Boot + MySQL based project that uses a Module Architecture to add
functionality.

The core of Watchtower (watchtower-core and watchtower-web) is a web application that handles
scanning code via pull request or file upload, displaying scan results and metrics, and managing
rulesets that will be applied to individual scans. Additionally, it handles authentication and
authorization of users, basic UI framing, logging, encryption of sensitive values, and Module
management.

## How TraceLink uses Watchtower

TraceLink ProdSec uses Watchtower to identify security-related and general code issues and report
them back to developers. Watchtower integrates with SCM pull request systems, so scans are run
automatically on pull request creation or update and issues are found before code is merged. This
enables TraceLink developers to resolve issues earlier in the Software Development Lifecycle (SDLC),
when they are less costly. Watchtower also aggregates results from many scan types to simplify the
scanning process and provide a single view of the most common issues across programming languages
and frameworks.

## Technologies

Spring Boot - For web server technology  
Flyway - For data migration  
MySQL - Tested with MySQL 8+  
Thymeleaf - For UI template rendering

## Installation

From source code, type `mvn clean package` in the root directory. After packaging, the server jar is
located in `watchtower-web/target/watchtower-web*.jar`.

To execute this jar, it requires a `JDBC_URL`, `JDBC_USERNAME`, and `JDBC_PASSWORD` or a link to a
configuration properties file as described in
the [Spring Docs](https://docs.spring.io/spring-boot/docs/current/reference/html/spring-boot-features.html#boot-features-external-config)
to supply these variables. An example can be
seen [here](./watchtower-web/src/main/resources/application-prd.yaml).

By default, the server runs on port 7777 and will configure the database tables automatically,
including any necessary migrations from version to version.

Watchtower can be run in a container using Docker and Docker Compose. A local setup is configured
in [Dockerfile](Dockerfile) and [docker-compose.yml](docker-compose.yml). Be sure to define the
environment variables listed in [Docker.env](Docker.env), then type `docker-compose up` in the root
directory to build the application and start the Docker container. The application will be hosted on
port 8080.

There are two files included to aid deploying to Kubernetes. [deploy](deploy.yaml) is a basic EKS deployment model that can be tailored to fit your needs and [watchtower-secrets](watchtower-secrets.yaml) can be used to supply the db secrets to your EKS system using the Kubernetes configMap. For production usage, it is recommended to put these secrets into a secrets manager, based on your application's needs and infrastructure's availability.

If you are running directly from the jar file and not via Docker, note that some modules require
specific setup as noted in their respective READMEs.

For development purposes and initial setup of Watchtower, an initial admin user is configured by
default in the Watchtower database.

| Username | Roles | 
|----------|-------| 
| admin | Full System Admin. Ability to access all Watchtower features. | 

This user is given a random password that is output to the Watchtower logs. Once Watchtower has been
deployed, set up a new, named admin user with a secure password and the Full System Admin role, and
then disable or delete the default admin user to prevent unauthorized access to Watchtower
configurations.

On every startup, Watchtower will check for this admin user. If the user exists and is not disabled,
Watchtower will automatically reset the password and output it to the logs. If the user doesn't
exist, Watchtower will ensure a user does exist that has sufficient privileges to assign roles and
privileges. If such a user does not exist, Watchtower will re-create the admin and grant it Full
System Admin so that administrators cannot get locked out while modifying users or roles.

## Authentication

There are two built-in ways to authenticate to Watchtower.

1. "Local" Authentication - Usernames and hashed passwords are stored in the database and users authenticate to Watchtower directly. This is configured by default. A basic password checking policy class is installed already [here](./watchtower-core/src/main/java/com/tracelink/appsec/watchtower/core/auth/service/checker/ComplexityUserPasswordRequirementsChecker.java), implementors can override this in configuration classes as done [here](./watchtower-core/src/main/java/com/tracelink/appsec/watchtower/core/configuration/WatchtowerConfiguration.java). 
2. SSO Authentication - Users login to a separate system which grants access to Watchtower via Open ID Connect. Configuration is handled via application properties, and requires a `CLIENT_ID`, `CLIENT_SECRET`, and `ISSUER_URI` supplied on the command line or in a file as in [here](./watchtower-web/src/main/resources/application-prd.yaml).

In addition, any user can create an API key + Secret that can be used for programmatic access via
Basic Auth. This Api key is granted the same privileges as the owning user.

By default, there is a self-registration process that allows a user to join Watchtower and is assigned a default role as described in the Authorization section. This registration can be turned off by setting the configuration `watchtower.allowRegistration` to false. This could be used once the app is migrated to SSO and at least one local user account is created to protect against duplicate accounts.

At startup, an asynchronous event will trigger to recover from downtime. This searches SCMs for Pull Requests that have not been scanned in each configured repository and adds them to the scanning queue. This can be disabled by setting the configuration `watchtower.runAfterStartup` to false.



## Authorization

Watchtower defines several roles and privileges in order to restrict access to resources on the
server. Individual privileges are grouped into roles, which can then be assigned to users. On
install, Watchtower creates a "Full System Admin" role and grants it all privileges, including any
that a Module needs.

An administrator can configure a role with any number of privileges and mark it as being the "
default" role. When a new user is created the user is automatically assigned the default role.
Otherwise the user will be assigned no roles or privileges. A user with zero roles represents the
most basic user with the least amount of privilege.

Administrators can see a list of all privileges in the system along with a description in order to
determine what privileges to give to a role or user.

## What is a Module?

Modules allow for the customization of Watchtower by adding different types of rules and scans. A
module defines how to perform a scan, given a ruleset and source code, as well as how to store rule
information on the server and how to design, import/export, or edit a rule. Each module supports the
following functionality:

- Create a new type of rule that can be assigned to rulesets
- Register a scanner that will be executed as part of any scan whose ruleset contains rules for this
  module
- Register a rule editor that provides a UI to edit rule information
- Register a ruleset interpreter that can import and export rules
- Register a rule designer that provides a UI to manually test and add rules to Watchtower
- Register privileges that the modules use to authorize user actions
- Register a database schema history table owned by the module
- Register a database migrations location that allows implementors to manage database tables
- Access JPA Repositories and Entities to manage rows in the database tables for this module's rule
  schema

**Note:** We recommend that all modules maintain their own schema history table and migrations
location. This allows each module to be fully independent of both Watchtower Core and other modules,
so that modules can be easily added or removed from a deployment.

## Modules Available

| Module | Description | Documentation Link |
|--------|-------------|--------------------|
| Checkov | This module integrates the Python [Checkov](https://www.checkov.io/) scanner into Watchtower to scan infrastructure-as-code and detect misconfigurations. | [watchtower-module-checkov](./watchtower-module-checkov/README.md)|
| ESLint | This module integrate the [ESLint](https://eslint.org/) linter into Watchtower to scan JavaScript code for common problems. | [watchtower-module-eslint](./watchtower-module-eslint/README.md)|
| JSON | This module defines Watchtower rules using JSONPath expressions to scan JSON files for issues. | [watchtower-module-json](./watchtower-module-json/README.md)
| PMD | This module integrates the Java [PMD](https://pmd.github.io/) static code analyzer into Watchtower to scan Java, Ecmascript, Scala, and XML files. | [watchtower-module-pmd](./watchtower-module-pmd/README.md)
| Regex | This module defines Watchtower rules using Regex expressions to scan files of many types for issues. | [watchtower-module-regex](./watchtower-module-regex/README.md)|

## Customization

There are a number of ways to customize your own installation of Watchtower.

### Choosing Modules

An installation can be modified to include a subset of the provided modules, or your own custom
modules by either modifying the pom file of [watchtower-web](./watchtower-web/pom.xml) or providing
references to your custom module jars on the classpath. Any modules found in your execution's
classpath will be automatically included and installed in your Watchtower deployment.

### Creating Custom Modules

While we have provided a number of modules to use, it is likely there are plenty of other modules
that can and should be created. You may create a custom module following the existing modules as an
example. If you feel that a custom module might be useful to others, please
consider [contributing](#contributions) to this project.

## Rules and Rulesets

Rules are at the center of Watchtower functionality. Each module may define additional information
stored in its rules, but Watchtower Core specifies some data that is common to all rules.

- Name: the name of the rule
- Author: user who created the rule
- Message: a message describing the issue that the rule identifies, which will be displayed to the
  user
- External URL: a link to additional information about the issue
- Priority: an indication of the severity of the issue, ranging from High to Low

Rules on their own, however, have no meaning. Watchtower uses rulesets to define which rules should
be applied to code during a particular scan. Rulesets can be created and edited via the Watchtower
UI. They can contain rules from multiple different modules and support a hierarchical structure, so
that one ruleset may be composed of several base rulesets. To enable these configurations, rulesets
are separated into two categories: primary and supporting. Primary rulesets may contain individual
rules, other primary rulesets, or other supporting rulesets, whereas supporting rulesets can only
contain individual rules or other supporting rulesets. Scans may only be run on a primary ruleset.

## Scan Types

Watchtower supports the following scan types:

- Pull Request Scans
- Upload Scans

### Pull Request Scans

Pull request scans are designed to integrate with an SCM tool to automate the scanning process and
identify issues early in the SDLC. There are two steps needed to configure pull request scans.
First, set up a webhook on the SCM that sends a request to Watchtower's "/rest/scan/" endpoint every
time a pull request is created or updated, automatically triggering the Watchtower scan. Then
configure API credentials in Watchtower in order to authenticate to the SCM and post scan results.

Watchtower will comment the results of the scan directly on the pull request, so that feedback is
immediately available to developers. The results distinguish between issues that are newly added in
the pull request, and those that are preexisting. Additionally, Watchtower can enforce a "blocking
mode" for pull requests, so that the pull request cannot be merged until new issues are resolved.

Rulesets for pull request scans are configured per Git repository. A default ruleset can be enabled
which will automatically be applied to any new repositories that are scanned. It is also possible to
mark a repository as exempt from Watchtower scans.

Pull request scans are currently implemented to integrate with Bitbucket Cloud.

### Upload Scans

Upload scans provide a way to manually scan code for issues. The code to scan is uploaded as a zip
file and then the ruleset to apply is specified before the scan can begin. Watchtower provides the
user with a ticket number for their scan, which they can use to check scan status and access
results. While not automated, upload scans provide a way to get a baseline of issues in all the
files of a project, rather than only reporting on the subset of files that appear in a pull request.

Watchtower provides a [CLI](./watchtower-cli/README.md) and
a [Maven plugin](./watchtower-maven-plugin/README.md) to perform upload scans during the development
phase of the SDLC.

## Database Column Encryption

Watchtower provides a system of encryption for database values that are sensitive and should not be
stored in plain text. Watchtower uses a Key-Encryption-Key (KEK) scheme of encryption, where a
master KEK is provided at the time of deployment and is used to encrypt and decrypt a collection of
data encryption keys (DEKs). The DEKs in turn encrypt and decrypt actual database values that need
additional protection.

### Configuring Database Columns for Encryption

To configure encryption on a particular database column, simply add an `@Convert` annotation to the
field of any entity class, and specify a converter class inside the annotation. For Watchtower
encryption to work, the converter class must extend the `AbstractEncryptedAttributeConverter`.
Watchtower has a `StringEncryptedAttributeConverter` to handle the most common case of string
encryption, but custom converters can be added to support additional use cases. Note that each
converter class corresponds to a single DEK. Implementers may choose to use a single converter for
all encrypted columns, or extend base converters to enable different converters (and therefore keys)
for different entities and/or columns. See
the [BBCloudIntegrationEntity](./watchtower-core/src/main/java/com/tracelink/appsec/watchtower/core/scan/scm/bb/BBCloudIntegrationEntity.java)
class for an example of how to use the `StringEncryptedAttributeConverter`.

An encryption converter can be added to a column at any time, whether it existed in a previous
deployment of Watchtower or not. If there is existing, plaintext data in that column of the database
when Watchtower starts up, it will be automatically encrypted using the converter.

### Configuring Encryption Type and Supplying the KEK

Once the database columns requiring encryption have been specified, Watchtower needs a KEK in order
to start encryption. The key is supplied through the application properties defined in the
watchtower-web project. An example of this is shown
in [application-prd.yaml](./watchtower-web/src/main/resources/application-prd.yaml). First
set `watchtower.encryption.type: environment` (which simply indicates that the KEKs are provided via
environment variables), and then provide a current KEK keystore in PKCS12 format, along with a
keystore password. When Watchtower starts up, it will configure encryption with the provided KEK.

If none of the `watchtower.encryption.*` properties are set, Watchtower defaults
to `watchtower.encryption.type: none`, and will not perform any encryption on database columns.

### Configuring KEK Rotation

To rotate the KEK, set the `watchtower.encryption.environment.currentKeyStorePath`
and `watchtower.encryption.environment.currentKeyStorePassword` with the values for the new KEK.
Then provide the old keystore path and password using the
properties `watchtower.encryption.environment.previousKeyStorePath`
and `watchtower.encryption.environment.previousKeyStorePassword`. When Watchtower starts up, it will
rotate the KEK so that all DEKs are encrypted with the new KEK.

The next time Watchtower is deployed, the old keystore path and password can be dropped as they are
no longer needed. Be sure to check the Watchtower log for errors during KEK rotation and see that
the KEK rotation completes. If Watchtower goes down during KEK rotation, restart Watchtower with the
same current and previous keystores and Watchtower should be able to recover.

### Configuring Database Decryption

To decrypt all database values that have been encrypted by Watchtower, provide the current keystore
path and password as usual, then specify one additional
property: `watchtower.encryption.environment.decryptMode: true`. When Watchtower starts up, it will
decrypt all columns that are currently encrypted in the database, and will delete any DEKs the next
time Watchtower is shut down. For the following deployment of Watchtower,
all `watchtower.encryption.*`
variables can be removed from the application.properties file to disable encryption entirely.

### Managing DEK Rotations

Watchtower contains an admin page to view the current DEKs and manage their rotations. DEKs can be
rotated manually (if, for example, there is reason to believe they are compromised), or a schedule
can be set to automatically rotate all keys after a certain number of days.

## Contributions

Contributions are welcome in the form of Pull Requests and any suggestions are welcome as Issues.

If you are contributing a Pull Request, we ask that you follow some of our practices:

- Please use one of our [formatters](./formatters)
- Please ensure that all existing tests pass and any code written has at least 90% code coverage.
- Please provide a README file that follows our module README examples

When creating a new Module, please ensure that static content, templates and any other resources
live in a special folder in their respective packages to avoid name collisions. Please also ensure
that you do not unintentionally re-use an existing schema history table name, Module name, or URI as
this will clash with the other Module.

Several class selectors have been customized for the UI. These include:

`datatable-invert` will begin datatables listing in reverse order (mostly for incrementing IDs and dates)
`localizetime` will convert an html tag that exactly contains the epoch millis/seconds into a localized datetime string of the client's browser (Month Day, Year, Hours:Minutes:Seconds)

## Authors

[Chris Smith](https://github.com/tophersmith)  
[Maddie Cool](https://github.com/madisoncool)  
[Brigid Horan](https://github.com/brigidhoran)
