package eu.europa.esig.dss.pades;

import java.util.Date;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;

/**
 * Defines a list of common PAdES parameters between signature and timestamps
 *
 */
public interface PAdESCommonParameters {
	
	/**
	 * Returns a claimed signing time
	 * @return {@link Date}
	 */
	Date getSigningDate();
	
	/**
	 * Returns a signature/timestampFieldId
	 * @return {@link String} field id
	 */
	String getFieldId();
	
	/**
	 * Returns Filter value
	 * @return {@link String} filter
	 */
	String getFilter();
	
	/**
	 * Returns SubFilter value
	 * @return {@link String} subFilter
	 */
	String getSubFilter();
	
	/**
	 * Returns {@link SignatureImageParameters} for field's visual representation
	 * @return {@link SignatureImageParameters}
	 */
	SignatureImageParameters getImageParameters();
	
	/**
	 * Returns a length of the reserved /Contents attribute
	 * @return int content size
	 */
	int getContentSize();
	
	/**
	 * Returns a DigestAlgorithm to be used to hash the signed/timestamped data
	 * @return {@link DigestAlgorithm}
	 */
	DigestAlgorithm getDigestAlgorithm();

}
