package com.tracelink.appsec.watchtower.core.scan.image.api;

import com.tracelink.appsec.watchtower.core.scan.IWatchtowerApi;
import com.tracelink.appsec.watchtower.core.scan.image.ImageScan;
import com.tracelink.appsec.watchtower.core.scan.image.ImageSecurityReport;
import com.tracelink.appsec.watchtower.core.scan.image.entity.ImageViolationEntity;
import java.util.List;

/**
 * Interface to extend {@link IWatchtowerApi} methods to include support for image scan actions.
 *
 * @author csmith
 */
public interface IImageApi extends IWatchtowerApi {

	void rejectImage(ImageScan image, List<ImageViolationEntity> violations);

	ImageSecurityReport getSecurityReportForImage(ImageScan image);
}
