package com.tracelink.appsec.watchtower.core.module.scanner;

import com.tracelink.appsec.watchtower.core.scan.code.CodeScanConfig;

public abstract class AbstractCodeScanner implements IScanner<CodeScanConfig> {
	@Override
	public Class<CodeScanConfig> getSupportedConfigClass() {
		return CodeScanConfig.class;
	}
}
