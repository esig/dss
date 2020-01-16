package eu.europa.esig.dss.model;

import java.io.Serializable;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;

public interface SerializableTimestampParameters extends Serializable {
	
	/**
	 * Returns a DigestAlgorithm to be used to hash a data to be timestamped
	 * 
	 * @return {@link DigestAlgorithm}
	 */
	DigestAlgorithm getDigestAlgorithm();

}
