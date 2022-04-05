package com.tracelink.appsec.watchtower.core.scan.api.image;

import com.tracelink.appsec.watchtower.core.scan.api.IWatchtowerApi;
import com.tracelink.appsec.watchtower.core.scan.image.ImageScan;
import com.tracelink.appsec.watchtower.core.scan.image.ImageSecurityReport;

public interface IImageRepoApi extends IWatchtowerApi {

	void register();

	void rejectImage(ImageScan image);

	ImageSecurityReport getSecurityReportForImage(ImageScan image);

}
