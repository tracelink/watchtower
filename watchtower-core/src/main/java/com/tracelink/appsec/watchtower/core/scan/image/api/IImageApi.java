package com.tracelink.appsec.watchtower.core.scan.image.api;

import java.util.List;

import com.tracelink.appsec.watchtower.core.scan.IWatchtowerApi;
import com.tracelink.appsec.watchtower.core.scan.image.ImageScan;
import com.tracelink.appsec.watchtower.core.scan.image.ImageSecurityReport;
import com.tracelink.appsec.watchtower.core.scan.image.entity.ImageViolationEntity;

public interface IImageApi extends IWatchtowerApi {
	void register();

	void rejectImage(ImageScan image, List<ImageViolationEntity> violations);

	ImageSecurityReport getSecurityReportForImage(ImageScan image);
}
