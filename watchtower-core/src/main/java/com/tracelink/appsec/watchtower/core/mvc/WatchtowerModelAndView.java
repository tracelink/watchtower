package com.tracelink.appsec.watchtower.core.mvc;

import java.util.ArrayList;
import java.util.List;

import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.View;

/**
 * A special ModelAndView to handle the Watchtower "Well View" and Flash attributes for
 * notifications
 *
 * @author bhoran
 *
 */
public class WatchtowerModelAndView extends ModelAndView {

	/**
	 * the key for the "well view"
	 */
	public static final String CONTENT_VIEW_NAME = "contentViewName";

	/**
	 * the name of the framing HTML for the Watchtower view
	 */
	public static final String DEFAULT_VIEW_TEMPLATE = "fragments/container";

	/**
	 * Attribute key to show a green notification in the Watchtower View
	 */
	public static final String SUCCESS_NOTIFICATION = "success";

	/**
	 * Attribute key to show a red notification in the Watchtower View
	 */
	public static final String FAILURE_NOTIFICATION = "failure";

	private final List<String> styles = new ArrayList<String>();
	private final List<String> scripts = new ArrayList<String>();

	/**
	 * Create the Watchtower ModelAndView using the specified view name as the "well view".
	 *
	 * @param contentViewName the name of the template file to use to show the "well view"
	 */
	public WatchtowerModelAndView(String contentViewName) {
		setViewName(DEFAULT_VIEW_TEMPLATE);
		addObject(CONTENT_VIEW_NAME, contentViewName);
		addObject("styles", styles);
		addObject("scripts", scripts);
	}

	/**
	 * Adds a style to the Watchtower View (added in the HTML head). This is a reference to the
	 * "styles/" location which should be under "/src/main/resources/static/styles/"
	 *
	 * @param style the css style file to use
	 * @return this Watchtower ModelAndView
	 */
	public WatchtowerModelAndView addStyleReference(String style) {
		styles.add(style);
		return this;
	}

	/**
	 * Adds a script to the Watchtower View (added in the HTML head). This is a reference to the
	 * "scripts/" location which should be under "/src/main/resources/static/scripts/"
	 *
	 * @param script the js script file to use
	 * @return this Watchtower ModelAndView
	 */
	public WatchtowerModelAndView addScriptReference(String script) {
		scripts.add(script);
		return this;
	}

	/**
	 * Setting the view name also removes all Watchtower logic and styles/scripts.
	 *
	 * This reverts the Watchtower ModelAndView to a simple ModelAndView
	 */
	@Override
	public void setViewName(String viewName) {
		this.getModel().remove(CONTENT_VIEW_NAME);
		this.getModel().remove("styles");
		this.getModel().remove("scripts");
		super.setViewName(viewName);
	}

	/**
	 * Setting the view also removes all Watchtower logic and styles/scripts.
	 *
	 * This reverts the Watchtower ModelAndView to a simple ModelAndView
	 */
	@Override
	public void setView(View view) {
		this.getModel().remove(CONTENT_VIEW_NAME);
		this.getModel().remove("styles");
		this.getModel().remove("scripts");
		super.setView(view);
	}

	/**
	 * Adds an error message to this MAV. This is displayed as a red banner at the top of the view's
	 * 
	 * @param error the error message
	 */
	public void addErrorMessage(String error) {
		this.addObject(WatchtowerModelAndView.FAILURE_NOTIFICATION, error);
	}

	/**
	 * Adds an success message to this MAV. This is displayed as a green banner at the top of the
	 * view's page
	 * 
	 * @param success the success message
	 */
	public void addSuccessMessage(String success) {
		this.addObject(WatchtowerModelAndView.SUCCESS_NOTIFICATION, success);
	}
}
