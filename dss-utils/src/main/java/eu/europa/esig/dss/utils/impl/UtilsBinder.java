package eu.europa.esig.dss.utils.impl;

import eu.europa.esig.dss.utils.IUtilsFactory;

/**
 * Default implementation which is never called (skipped in build)
 */
public class UtilsBinder {

	private static final UtilsBinder SINGLETON = new UtilsBinder();

	public static final UtilsBinder getSingleton() {
		return SINGLETON;
	}

	private UtilsBinder() {
		throw new UnsupportedOperationException("This code should have never made it into dss-utils.jar");
	}

	public IUtilsFactory getUtilsFactory() {
		throw new UnsupportedOperationException("This code should have never made it into dss-utils.jar");
	}

}
