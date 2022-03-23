package com.tracelink.appsec.watchtower.core.scan;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import org.apache.commons.lang3.StringUtils;
import org.springframework.stereotype.Service;

import com.tracelink.appsec.watchtower.core.module.ModuleException;
import com.tracelink.appsec.watchtower.core.module.scanner.IScanner;

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
	private Map<String, IScanner> scanners = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);

	/**
	 * Registers a scanner with this service.
	 *
	 * @param module  name of the module associated with the given scanner
	 * @param scanner scanner associated with the given module name
	 * @throws IllegalArgumentException if the name or scanner are null
	 * @throws ModuleException          if there is already a scanner associated with the given
	 *                                  module
	 */
	public void registerScanner(String module, IScanner scanner)
			throws IllegalArgumentException, ModuleException {
		if (StringUtils.isBlank(module) || scanner == null) {
			throw new IllegalArgumentException("Module and scanner cannot be null.");
		}
		if (scanners.containsKey(module)) {
			throw new ModuleException("A scanner for the given module already exists: " + module);
		}
		scanners.put(module, scanner);
	}

	@SuppressWarnings("unchecked")
	public <C extends AbstractScanConfig> Collection<IScanner<C>> getScanners(
			Class<C> configClass) {
		List<IScanner<C>> scanners = new ArrayList<>();
		for (IScanner<?> scanner : this.scanners.values()) {
			if (configClass.isAssignableFrom(scanner.getSupportedConfigClass())) {
				scanners.add((IScanner<C>) scanner);
			}
		}
		return scanners;
	}

	public boolean isEmpty() {
		return this.scanners.isEmpty();
	}
}
