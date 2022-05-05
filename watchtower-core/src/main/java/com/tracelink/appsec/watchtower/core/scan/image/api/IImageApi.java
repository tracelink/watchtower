package com.tracelink.appsec.watchtower.core.scan.image.api;

import java.util.List;

import com.tracelink.appsec.watchtower.core.scan.IWatchtowerApi;
import com.tracelink.appsec.watchtower.core.scan.image.ImageScan;
import com.tracelink.appsec.watchtower.core.scan.image.ImageSecurityReport;
import com.tracelink.appsec.watchtower.core.scan.image.entity.ImageViolationEntity;

/**
 * Interface to extend {@link IWatchtowerApi} methods to include support for image scan actions.
 *
 * @author csmith
 */
public interface IImageApi extends IWatchtowerApi {

	/**
	 * If the image is found to be invalid or bad in some way, this method is called to reject the
	 * image from its repository. This may mean blocking usage, sending messages, or removing the
	 * image entirely.
	 * 
	 * @param image      the image to reject
	 * @param violations the violations found for this image
	 */
	void rejectImage(ImageScan image, List<ImageViolationEntity> violations);

	/**
	 * Given an image, get or create the {@linkplain ImageSecurityReport} for the image.
	 * 
	 * @param image the image to get the report for
	 * @return a security report detailing issues found in the given image
	 */
	ImageSecurityReport getSecurityReportForImage(ImageScan image);
}
