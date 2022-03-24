package com.tracelink.appsec.watchtower.core.scan.image.ecr;

import java.util.List;

import com.tracelink.appsec.watchtower.core.scan.image.ContainerImage;

public class ImageSecurityReport {
	private ContainerImage image;
	private List<ImageSecurityFinding> findings;

}
