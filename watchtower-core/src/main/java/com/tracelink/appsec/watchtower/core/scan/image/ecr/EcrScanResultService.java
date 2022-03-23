package com.tracelink.appsec.watchtower.core.scan.image.ecr;

import java.util.List;

import org.springframework.stereotype.Service;

import com.tracelink.appsec.watchtower.core.report.ScanError;
import com.tracelink.appsec.watchtower.core.scan.api.image.ecr.EcrImage;
import com.tracelink.appsec.watchtower.core.scan.image.ecr.entity.EcrViolationEntity;

@Service
public class EcrScanResultService {

	public void saveReport(EcrImage image, long startTime, List<EcrViolationEntity> violations,
			List<ScanError> errors) {
		// TODO Auto-generated method stub

	}

}
