package com.tracelink.appsec.watchtower.core.scan.image;

public interface IImageRepoApi<I> {

	boolean hasAccess();

	void register();

	void rejectImage(I image);

}
