package com.tracelink.appsec.watchtower.core.scan.image.api;

import com.tracelink.appsec.watchtower.core.scan.IWatchtowerApi;
import com.tracelink.appsec.watchtower.core.scan.image.ImageScan;
import com.tracelink.appsec.watchtower.core.scan.image.ImageSecurityReport;

public interface IImageApi extends IWatchtowerApi {
	void register();

	void rejectImage(ImageScan image);

	ImageSecurityReport getSecurityReportForImage(ImageScan image);
}
