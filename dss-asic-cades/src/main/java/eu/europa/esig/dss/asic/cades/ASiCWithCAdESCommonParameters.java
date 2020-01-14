package eu.europa.esig.dss.asic.cades;

import java.io.Serializable;
import java.util.Date;

import eu.europa.esig.dss.asic.common.ASiCParameters;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;

public interface ASiCWithCAdESCommonParameters extends Serializable {

	/**
	 * Returns ASiC container parameters
	 * 
	 * @return {@link ASiCParameters}
	 */
	ASiCParameters aSiC();
	
	/**
	 * Returns a DigestAlgorithm to be used to hash a data to be timestamped
	 * 
	 * @return {@link DigestAlgorithm}
	 */
	DigestAlgorithm getDigestAlgorithm();
	
	/**
	 * Returns a signing date
	 * @return {@link Date}
	 */
	Date getZipCreationDate();

}
