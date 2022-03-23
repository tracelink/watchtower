package com.tracelink.appsec.watchtower.core.module.scanner;

import com.tracelink.appsec.watchtower.core.scan.image.ImageScanConfig;

public abstract class AbstractImageScanner implements IScanner<ImageScanConfig> {
	@Override
	public Class<ImageScanConfig> getSupportedConfigClass() {
		return ImageScanConfig.class;
	}
}
