package com.tracelink.appsec.watchtower.core.scan.image;

import java.util.List;

/**
 * DAO collecting findings found during an Image Scan
 * 
 * @author csmith
 *
 */
public class ImageSecurityReport {
	private ImageScan image;
	private List<ImageSecurityFinding> findings;

	public ImageSecurityReport(ImageScan image) {
		this.image = image;
	}

	public ImageScan getImage() {
		return image;
	}

	public List<ImageSecurityFinding> getFindings() {
		return findings;
	}

	public void setFindings(List<ImageSecurityFinding> findings) {
		this.findings = findings;
	}

}
