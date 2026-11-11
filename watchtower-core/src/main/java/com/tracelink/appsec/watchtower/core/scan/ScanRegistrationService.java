package com.tracelink.appsec.watchtower.core.scan;

import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.TreeSet;

import org.apache.commons.lang3.StringUtils;
import org.springframework.stereotype.Service;

import com.tracelink.appsec.watchtower.core.module.ModuleException;
import com.tracelink.appsec.watchtower.core.module.scanner.ICodeScanner;
import com.tracelink.appsec.watchtower.core.module.scanner.IImageScanner;
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
	@org.springframework.beans.factory.annotation.Autowired(required=false)
 private com.tracelink.appsec.watchtower.core.module.ModuleControlService moduleControls;

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
	public void registerScanner(String module, IScanner<?, ?> scanner)
			throws IllegalArgumentException, ModuleException {
		if (StringUtils.isBlank(module) || scanner == null) {
			throw new IllegalArgumentException("Module and scanner cannot be null.");
		}
		if (moduleControls != null) moduleControls.register(module);
  if (scanner instanceof ICodeScanner) {
			if (codeScanners.containsKey(module)) {
				throw new ModuleException(
						"A scanner for the given module already exists: " + module);
			}
			codeScanners.put(module, (ICodeScanner) scanner);
		} else if (scanner instanceof IImageScanner) {
			if (imageScanners.containsKey(module)) {
				throw new ModuleException(
						"A scanner for the given module already exists: " + module);
			}
			imageScanners.put(module, (IImageScanner) scanner);
		}
	}

	public Collection<ICodeScanner> getCodeScanners() {
		return moduleControls == null ? List.copyOf(codeScanners.values()) : codeScanners.entrySet().stream()
   .map(e -> (ICodeScanner)new com.tracelink.appsec.watchtower.core.module.ControlledCodeScanner(e.getKey(),e.getValue(),moduleControls)).toList();
	}

	/**
	 * Whether the given module's code scanner produces sensitive findings (see
	 * {@link ICodeScanner#isSensitive()}).
	 *
	 * @param module the module name, as reported by a rule's {@code getModule()}
	 * @return true only if a sensitive code scanner is registered under that module name
	 */
	public boolean isSensitiveModule(String module) {
		if (StringUtils.isBlank(module)) {
			return false;
		}
		ICodeScanner scanner = codeScanners.get(module);
		return scanner != null && scanner.isSensitive();
	}

	public boolean hasCodeScanners() {
		return !this.codeScanners.isEmpty();
	}

	public Collection<IImageScanner> getImageScanners() {
		return moduleControls == null ? List.copyOf(imageScanners.values()) : imageScanners.entrySet().stream()
   .map(e -> (IImageScanner)new com.tracelink.appsec.watchtower.core.module.ControlledImageScanner(e.getKey(),e.getValue(),moduleControls)).toList();
	}

	public boolean hasImageScanners() {
		return !this.imageScanners.isEmpty();
	}

	/**
	 * Every registered scanner by module name, wrapped in its module policy so
	 * {@link IScanner#isDisabled()} reflects the current execution setting.
	 *
	 * @return module name to scanner, case-insensitively sorted by module
	 */
	public Map<String, IScanner<?, ?>> getScannersByModule() {
		Map<String, IScanner<?, ?>> byModule = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
		codeScanners.forEach((module, scanner) -> byModule.put(module, moduleControls == null ? scanner
				: new com.tracelink.appsec.watchtower.core.module.ControlledCodeScanner(module, scanner, moduleControls)));
		imageScanners.forEach((module, scanner) -> byModule.put(module, moduleControls == null ? scanner
				: new com.tracelink.appsec.watchtower.core.module.ControlledImageScanner(module, scanner, moduleControls)));
		return java.util.Collections.unmodifiableMap(byModule);
	}

	/**
	 * Names of every registered scanner module, independent of the scan type it supports.
	 *
	 * @return case-insensitively sorted scanner module names
	 */
	public List<String> getScannerNames() {
		TreeSet<String> names = new TreeSet<>(String.CASE_INSENSITIVE_ORDER);
		names.addAll(codeScanners.keySet());
		names.addAll(imageScanners.keySet());
		return List.copyOf(names);
	}
}
