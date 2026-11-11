package com.tracelink.appsec.watchtower.core.module.scanner;

/** Remote assessments require a durable orchestrator, never a generic rule-test invocation. */
public enum ExecutionCapability { LOCAL, REMOTE_SERVICE }
