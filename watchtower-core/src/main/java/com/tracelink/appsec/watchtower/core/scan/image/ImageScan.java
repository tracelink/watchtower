package com.tracelink.appsec.watchtower.core.scan.image;

import com.tracelink.appsec.watchtower.core.rest.scan.AbstractScan;

/**
 * Abstract class to hold necessary info for an image scan request.
 *
 * @author csmith, mcool
 */
public abstract class ImageScan extends AbstractScan {

	/**
	 * The hostname:port or other identifier to access this container registry
	 */
	private String registry;
	/**
	 * The path to an image (everything after host:port/registry id and before the : for tag)
	 */
	private String repository;
	/**
	 * The tag name (everything after the :)
	 */
	private String tag;

	public ImageScan(String apiLabel) {
		super(apiLabel);
	}

	public String getScanName() {
		return getRepository() + ":" + getTag();
	}

	public String getRegistry() {
		return registry;
	}

	public void setRegistry(String registry) {
		this.registry = registry;
	}

	public String getRepository() {
		return repository;
	}

	public void setRepository(String repository) {
		this.repository = repository;
	}

	public String getTag() {
		return tag;
	}

	public void setTag(String tag) {
		this.tag = tag;
	}
}
