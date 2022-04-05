package com.tracelink.appsec.watchtower.core.scan.api.image.ecr;

import com.tracelink.appsec.watchtower.core.scan.api.image.IImageRepoApi;
import com.tracelink.appsec.watchtower.core.scan.image.ImageScan;
import com.tracelink.appsec.watchtower.core.scan.image.ImageSecurityReport;

public class EcrApi implements IImageRepoApi {

	/**
	 * Check if this api has access to all apis it needs
	 */
	@Override
	public void testClientConnection() {
		// TODO Auto-generated method stub
	}

	/**
	 * Register the Lambda webhook so that ECR can send events to Watchtower
	 */
	@Override
	public void register() {
		// TODO Auto-generated method stub

	}

	/**
	 * Notify the originating ECR that this image is bad. This is done by deleting the image from
	 * ECR
	 */
	@Override
	public void rejectImage(ImageScan image) {
		// TODO Auto-generated method stub

	}

	/**
	 * Get an ECR image's security scan report from ECR
	 * 
	 * @param image the Image to investigate
	 * @return the security report
	 */
	public ImageSecurityReport getSecurityReportForImage(ImageScan image) {
		// TODO Auto-generated method stub
		return null;
	}

}
