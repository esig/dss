package eu.europa.esig.dss.asic.cades;

import java.util.Date;

import eu.europa.esig.dss.asic.common.ASiCCommonParameters;

public interface ASiCWithCAdESCommonParameters extends ASiCCommonParameters {
	
	/**
	 * Returns a signing date
	 * @return {@link Date}
	 */
	Date getZipCreationDate();

}
