package com.tracelink.appsec.watchtower.core.scan.presentation;

import java.util.Optional;

import org.springframework.security.core.Authentication;

/**
 * Lets a module offer a link on a pull request report's finding, e.g. the secrets module's
 * "Allowlist…". Core shows the first action any provider returns; it never knows what the
 * action does. Register as a bean.
 *
 * @author Watchtower
 */
public interface IFindingActionProvider {

	/**
	 * @param finding        the finding
	 * @param authentication the viewer, to check the privilege the action needs
	 * @return the action, or empty if this provider has none for the finding or the viewer
	 */
	Optional<FindingAction> actionFor(FindingContext finding, Authentication authentication);
}
