package com.tracelink.appsec.watchtower.core.scan.image.api.ecr;

import java.util.List;

import com.tracelink.appsec.watchtower.core.scan.apiintegration.ApiIntegrationException;
import com.tracelink.appsec.watchtower.core.scan.image.ImageScan;
import com.tracelink.appsec.watchtower.core.scan.image.ImageSecurityReport;
import com.tracelink.appsec.watchtower.core.scan.image.api.IImageApi;
import com.tracelink.appsec.watchtower.core.scan.image.entity.ImageViolationEntity;

public class EcrApi implements IImageApi {

	public EcrApi(EcrIntegrationEntity ecrIntegrationEntity) {
		// TODO Auto-generated constructor stub
	}

	@Override
	public void testClientConnection() throws ApiIntegrationException {
		// TODO Auto-generated method stub

	}

	@Override
	public void register() {
		// TODO Auto-generated method stub

	}

	@Override
	public void rejectImage(ImageScan image, List<ImageViolationEntity> violations) {
		// TODO Auto-generated method stub

	}

	@Override
	public ImageSecurityReport getSecurityReportForImage(ImageScan image) {
		// TODO Auto-generated method stub
		return null;
	}

}
