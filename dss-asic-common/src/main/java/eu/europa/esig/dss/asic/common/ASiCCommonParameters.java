package eu.europa.esig.dss.asic.common;

import eu.europa.esig.dss.model.SerializableTimestampParameters;

/**
 * Common parameters between signature and timestamp
 *
 */
public interface ASiCCommonParameters extends SerializableTimestampParameters {

	/**
	 * Returns ASiC container parameters
	 * 
	 * @return {@link ASiCParameters}
	 */
	ASiCParameters aSiC();

}
