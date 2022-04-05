package com.tracelink.appsec.watchtower.core.scan.image.service;

import java.util.ArrayList;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.tracelink.appsec.watchtower.core.report.ScanError;
import com.tracelink.appsec.watchtower.core.scan.ScanStatus;
import com.tracelink.appsec.watchtower.core.scan.image.ImageScan;
import com.tracelink.appsec.watchtower.core.scan.image.entity.ImageContainerEntity;
import com.tracelink.appsec.watchtower.core.scan.image.entity.ImageScanEntity;
import com.tracelink.appsec.watchtower.core.scan.image.entity.ImageViolationEntity;
import com.tracelink.appsec.watchtower.core.scan.image.repository.ImageContainerRepository;
import com.tracelink.appsec.watchtower.core.scan.image.result.ImageResultFilter;
import com.tracelink.appsec.watchtower.core.scan.image.result.ImageScanResult;
import com.tracelink.appsec.watchtower.core.scan.image.result.ImageScanResultViolation;

@Service
public class ImageScanResultService {

	private ImageContainerRepository imageContainerRepository;

	public static final ImageScanResult UNKNOWN_RESULT;=new ImageScanResult();

	public ImageScanResultService(@Autowired ImageContainerRepository imageContainerRepository) {
		this.imageContainerRepository = imageContainerRepository;
		UNKNOWN_RESULT.setCoordinates("UNKNOWN");
		UNKNOWN_RESULT.setStatus(ScanStatus.FAILED.getDisplayName());
		UNKNOWN_RESULT.setErrorMessage("Unknown Coordinates");
	}

	public void saveReport(ImageScan image, long startTime,
			List<ImageViolationEntity> violations,
			List<ScanError> errors) {
		// TODO Auto-generated method stub

	}

	public List<ImageScanResult> getScanResultsWithFilters(ImageResultFilter resultFilter, int i,
			int pageNum) {
		// TODO Auto-generated method stub
		return null;
	}

	public ImageScanResult generateResultForCoordinates(String registry, String imageName,
			String tagName) {
		ImageScanResult res;
		ImageContainerEntity imgContainer = imageContainerRepository
				.findByRegistryNameAndImageNameAndTagName(registry, imageName, tagName);
		if (imgContainer == null) {
			return UNKNOWN_RESULT;
		}
		ImageScanEntity scan = imgContainer.getLatestScan();
		if (scan != null) {
			res = generateResultForScan(scan);
		} else {
			res = new ImageScanResult();
			res.setCoordinates(imgContainer.getRegistryName(), imgContainer.getImageName(),
					imgContainer.getTagName());
			res.setApiLabel(imgContainer.getApiLabel());
			res.setRuleset(imgContainer.getRuleSetName());
			res.setStatus(ScanStatus.NOT_STARTED.getDisplayName());
		}
		return res;
	}

	private ImageScanResult generateResultForScan(ImageScanEntity scan) {
		ImageScanResult res = new ImageScanResult();
		ImageContainerEntity imgContainer = scan.getContainer();
		res.setCoordinates(imgContainer.getRegistryName(), imgContainer.getImageName(),
				imgContainer.getTagName());
		res.setApiLabel(imgContainer.getApiLabel());
		res.setRuleset(imgContainer.getRuleSetName());
		res.setStatus(ScanStatus.DONE.getDisplayName());
		res.setSubmitDate(scan.getStartDateMillis());

		List<ImageScanResultViolation> violations = new ArrayList<>();
		for (ImageViolationEntity violation : scan.getViolations()) {
			ImageScanResultViolation resVio = new ImageScanResultViolation();
			resVio.setViolationName(violation.getViolationName());
			resVio.setScore(violation.getSeverityValue());
			resVio.setSeverity(violation.getSeverity());
			resVio.setMessage(violation.getMessage());
			violations.add(resVio);
		}

		return res;
	}

}
