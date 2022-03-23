package com.tracelink.appsec.watchtower.core.module.scanner;

import com.tracelink.appsec.watchtower.core.scan.scm.ScmScanConfig;

public abstract class AbstractScmScanner implements IScanner<ScmScanConfig> {
	@Override
	public Class<ScmScanConfig> getSupportedConfigClass() {
		return ScmScanConfig.class;
	}
}
