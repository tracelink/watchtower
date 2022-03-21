package com.tracelink.appsec.watchtower.core.scan.image.ecr;

import com.tracelink.appsec.watchtower.core.scan.image.IImageRepoApi;

public class EcrApi implements IImageRepoApi<EcrImage> {

	/**
	 * Check if this api has access to all apis it needs
	 */
	@Override
	public boolean hasAccess() {
		// TODO Auto-generated method stub
		return false;
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
	public void rejectImage(EcrImage image) {
		// TODO Auto-generated method stub

	}

	/**
	 * Get an ECR image's security scan report from ECR
	 * 
	 * @param image the Image to investigate
	 * @return the security report
	 */
	public EcrSecurityReport getSecurityReportForImage(EcrImage image) {
		// TODO Auto-generated method stub
		return null;
	}

}
