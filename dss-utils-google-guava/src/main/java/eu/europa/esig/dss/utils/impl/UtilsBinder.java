package eu.europa.esig.dss.utils.impl;

import eu.europa.esig.dss.utils.IUtilsFactory;
import eu.europa.esig.dss.utils.spi.UtilsFactoryBinder;

public class UtilsBinder implements UtilsFactoryBinder {

	private static final UtilsBinder SINGLETON = new UtilsBinder();

	public static final UtilsBinder getSingleton() {
		return SINGLETON;
	}

	private IUtilsFactory factory;

	private UtilsBinder() {
		factory = new GoogleGuavaUtilsFactory();
	}

	@Override
	public IUtilsFactory getUtilsFactory() {
		return factory;
	}

}
