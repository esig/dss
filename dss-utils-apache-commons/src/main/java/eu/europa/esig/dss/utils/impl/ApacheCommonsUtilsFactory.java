package eu.europa.esig.dss.utils.impl;

import eu.europa.esig.dss.utils.IUtils;
import eu.europa.esig.dss.utils.IUtilsFactory;

public class ApacheCommonsUtilsFactory implements IUtilsFactory {

	@Override
	public IUtils getUtils() {
		return new ApacheCommonsUtils();
	}

}
