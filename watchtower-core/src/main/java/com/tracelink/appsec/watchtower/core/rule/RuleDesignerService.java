package com.tracelink.appsec.watchtower.core.rule;

import java.util.List;
import java.util.TreeMap;
import java.util.stream.Collectors;

import org.apache.commons.lang3.StringUtils;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

import com.tracelink.appsec.watchtower.core.module.ModuleException;
import com.tracelink.appsec.watchtower.core.module.ModuleNotFoundException;
import com.tracelink.appsec.watchtower.core.module.designer.IRuleDesigner;
import com.tracelink.appsec.watchtower.core.module.designer.RuleDraftData;
import com.tracelink.appsec.watchtower.core.module.designer.RuleDesignerModelAndView;

/**
 * Provides business logic to register module designers and get their
 * {@link RuleDesignerModelAndView}
 * 
 * @author csmith
 *
 */
@Service
public class RuleDesignerService {

	/**
	 * Map from module name to designer implementation
	 */
	@org.springframework.beans.factory.annotation.Autowired(required=false)
 private com.tracelink.appsec.watchtower.core.module.ModuleControlService moduleControls;
 private boolean enabled(String module){return moduleControls==null||moduleControls.enabled(module);}
 /**
  * The file types an admin limited this module's scanner to in Scanner modules; empty when there is no
  * limit. A designer with a file extension warns when the rule's extension falls outside them.
  */
 public java.util.List<String> getFileTypes(String module){
  if(moduleControls==null)return java.util.List.of();
  var types=moduleControls.policy(module).fileTypes();
  return types==null?java.util.List.of():types;
 }

 private TreeMap<String, IRuleDesigner> designerMap =
			new TreeMap<>(String.CASE_INSENSITIVE_ORDER);

	/**
	 * Registers a designer with this service.
	 *
	 * @param module       name of the module the given designer is associated with
	 * @param ruleDesigner designer implementation for the given module
	 * @throws IllegalArgumentException if the name or designer are null
	 * @throws ModuleException          if there is already a designer associated with the given
	 *                                  module
	 */
	public void registerRuleDesigner(String module, IRuleDesigner ruleDesigner)
			throws IllegalArgumentException, ModuleException {
		if (StringUtils.isBlank(module) || ruleDesigner == null) {
			throw new IllegalArgumentException("Module name and designer cannot be null.");
		}
		if (designerMap.containsKey(module)) {
			throw new ModuleException("A designer for the given module already exists: " + module);
		}
		designerMap.put(module, ruleDesigner);
	}

	/**
	 * Return an ordered list of module names allowed by this authenticated user
	 * 
	 * @param auth The authentication object for this request
	 * @return an ordered list of module names that are accessible to the user
	 */
	public List<String> getKnownModulesForUser(Authentication auth) {
		/*
		 * get all authorities, filter if the designer says OK, then return the Module name(s) that
		 * match
		 */
		return designerMap.entrySet().stream()
				.filter(e -> enabled(e.getKey())).filter(e -> auth.getAuthorities().stream()
						.anyMatch(authority -> e.getValue().hasAuthority(authority.getAuthority())))
				.map(e -> e.getKey()).collect(Collectors.toList());
	}

	/**
	 * Gets the default designer module name. If no modules are configured, returns null
	 *
	 * @return default designer module name, or null if none exist
	 */
	public String getDefaultDesignerModule() {
		return designerMap.keySet().stream().filter(this::enabled).findFirst().orElse(null);
	}

	/**
	 * Given a designer name, return the default configuration of a designer MAV
	 *
	 * @param designer the designer to get a model for
	 * @return the default Designer Model for the Designer
	 * @throws ModuleNotFoundException if no designer matches the given type
	 */
	public RuleDesignerModelAndView getDefaultDesignerModelAndView(String designer)
			throws ModuleNotFoundException {
		if (!enabled(designer) || !designerMap.containsKey(designer.toLowerCase())) {
			throw new ModuleNotFoundException("No designer exists for the given type: " + designer);
		}
		return designerMap.get(designer.toLowerCase()).getDefaultRuleDesignerModelAndView();
	}

	/**
	 * The designer for a drafted rule: the same page, with the draft's rule and examples filled in.
	 *
	 * @param designer the designer to get a model for
	 * @param draft    the draft to show
	 * @throws ModuleNotFoundException if no enabled designer matches the given type
	 */
	public RuleDesignerModelAndView getPrefilledDesignerModelAndView(String designer, RuleDraftData draft)
			throws ModuleNotFoundException {
		if (!enabled(designer) || !designerMap.containsKey(designer.toLowerCase())) {
			throw new ModuleNotFoundException("No designer exists for the given type: " + designer);
		}
		return designerMap.get(designer.toLowerCase()).getPrefilledRuleDesignerModelAndView(draft);
	}

	/** The scanners that have a designer and are turned on, lower case. */
	public java.util.Set<String> enabledDesigners() {
		return designerMap.keySet().stream().filter(this::enabled).map(String::toLowerCase)
				.collect(Collectors.toCollection(java.util.TreeSet::new));
	}

	/**
	 * What a designer finds wrong with a draft meant for it, or null when it finds nothing. A module with no
	 * designer, or a disabled one, cannot take a draft.
	 */
	public String problemWithDraft(String designer, RuleDraftData draft) {
		if (designer == null || !enabled(designer) || !designerMap.containsKey(designer.toLowerCase())) {
			return "There is no designer for " + designer + " that is turned on.";
		}
		return designerMap.get(designer.toLowerCase()).validateDraft(draft);
	}

}
