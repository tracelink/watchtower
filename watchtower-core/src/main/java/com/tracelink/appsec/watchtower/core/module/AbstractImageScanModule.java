package com.tracelink.appsec.watchtower.core.module;

import com.tracelink.appsec.watchtower.core.module.scanner.IImageScanner;

/**
 * The Module is the main implementation for a Watchtower scanner.
 * <p>
 * It contains the necessary information to manage and design rules for the scanner in order to
 * function within Watchtower. It also contains functionality to store rules in the database and
 * perform database migrations. It does not provide any Spring controls. See
 * {@link WatchtowerModule} for that functionality, including JPA and Entity creation.
 *
 * @author mcool
 */
public abstract class AbstractImageScanModule extends AbstractModule<IImageScanner> {

}
