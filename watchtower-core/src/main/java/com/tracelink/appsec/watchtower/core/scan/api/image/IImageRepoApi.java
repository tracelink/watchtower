package com.tracelink.appsec.watchtower.core.scan.api.image;

import com.tracelink.appsec.watchtower.core.scan.api.IWatchtowerApi;
import com.tracelink.appsec.watchtower.core.scan.image.ContainerImage;

public interface IImageRepoApi extends IWatchtowerApi {

	void register();

	void rejectImage(ContainerImage image);

}
