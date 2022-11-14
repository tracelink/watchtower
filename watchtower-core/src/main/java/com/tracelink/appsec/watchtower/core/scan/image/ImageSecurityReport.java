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

	private boolean scanTimedOut;

	public ImageSecurityReport(ImageScan image) {
		this.image = image;
		this.scanTimedOut = false;
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
	public boolean getScanTimedOut() {
		return this.scanTimedOut;
	}
	public void setScanTimedOut(boolean timeout) {
		this.scanTimedOut = timeout;
	}

}
