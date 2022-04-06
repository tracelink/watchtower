package com.tracelink.appsec.watchtower.core.scan;

import java.util.Collection;
import java.util.Map;
import java.util.TreeMap;

import org.apache.commons.lang3.StringUtils;
import org.springframework.stereotype.Service;

import com.tracelink.appsec.watchtower.core.module.ModuleException;
import com.tracelink.appsec.watchtower.core.module.scanner.ICodeScanner;
import com.tracelink.appsec.watchtower.core.module.scanner.IImageScanner;

/**
 * Handles all logic around managing the scanners in the system
 *
 * @author csmith, mcool
 */
@Service
public class ScanRegistrationService {
	/**
	 * Map from module name to scanner implementation
	 */
	private Map<String, ICodeScanner> codeScanners = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
	private Map<String, IImageScanner> imageScanners = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);

	/**
	 * Registers a scanner with this service.
	 *
	 * @param module  name of the module associated with the given scanner
	 * @param scanner scanner associated with the given module name
	 * @throws IllegalArgumentException if the name or scanner are null
	 * @throws ModuleException          if there is already a scanner associated with the given
	 *                                  module
	 */
	public void registerScanner(String module, ICodeScanner scanner)
			throws IllegalArgumentException, ModuleException {
		if (StringUtils.isBlank(module) || scanner == null) {
			throw new IllegalArgumentException("Module and scanner cannot be null.");
		}
		if (codeScanners.containsKey(module)) {
			throw new ModuleException("A scanner for the given module already exists: " + module);
		}
		codeScanners.put(module, scanner);
	}

	public void registerScanner(String module, IImageScanner scanner)
			throws IllegalArgumentException, ModuleException {
		if (StringUtils.isBlank(module) || scanner == null) {
			throw new IllegalArgumentException("Module and scanner cannot be null.");
		}
		if (imageScanners.containsKey(module)) {
			throw new ModuleException("A scanner for the given module already exists: " + module);
		}
		imageScanners.put(module, scanner);
	}

	public Collection<ICodeScanner> getCodeScanners() {
		return this.codeScanners.values();
	}

	public boolean hasCodeScanners() {
		return !this.codeScanners.isEmpty();
	}

	public Collection<IImageScanner> getImageScanners() {
		return this.imageScanners.values();
	}

	public boolean hasImageScanners() {
		return !this.imageScanners.isEmpty();
	}
}
