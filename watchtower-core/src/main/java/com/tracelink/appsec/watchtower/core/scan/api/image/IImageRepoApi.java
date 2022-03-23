package com.tracelink.appsec.watchtower.core.scan.api.image;

import com.tracelink.appsec.watchtower.core.scan.api.IWatchtowerApi;

public interface IImageRepoApi<I> extends IWatchtowerApi {

	void register();

	void rejectImage(I image);

}
