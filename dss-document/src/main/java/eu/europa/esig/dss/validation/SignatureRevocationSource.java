package eu.europa.esig.dss.validation;

import java.util.List;

import eu.europa.esig.dss.spi.x509.revocation.RevocationToken;

public interface SignatureRevocationSource<T extends RevocationToken> {
	
	/**
	 * Retrieves the list of all {@link RevocationToken}s present in
	 * 'RevocationValues' element
	 * 
	 * NOTE: Applicable only for CAdES and XAdES revocation sources
	 * 
	 * @return list of {@link RevocationToken}s
	 */
	List<T> getRevocationValuesTokens();

	/**
	 * Retrieves the list of all {@link RevocationToken}s present in
	 * 'AttributeRevocationValues' element
	 * 
	 * NOTE: Applicable only for XAdES revocation source
	 * 
	 * @return list of {@link RevocationToken}s
	 */
	List<T> getAttributeRevocationValuesTokens();

	/**
	 * Retrieves the list of all {@link RevocationToken}s present in
	 * 'TimestampValidationData' element
	 * 
	 * NOTE: Applicable only for XAdES revocation source
	 * 
	 * @return list of {@link RevocationToken}s
	 */
	List<T> getTimestampValidationDataTokens();

	/**
	 * Retrieves the list of all {@link RevocationToken}s present in 'DSS'
	 * dictionary
	 * 
	 * NOTE: Applicable only for PAdES revocation source
	 * 
	 * @return list of {@link RevocationToken}s
	 */
	List<T> getDSSDictionaryTokens();

	/**
	 * Retrieves the list of all {@link RevocationToken}s present in 'VRI'
	 * dictionary
	 * 
	 * NOTE: Applicable only for PAdES revocation source
	 * 
	 * @return list of {@link RevocationToken}s
	 */
	List<T> getVRIDictionaryTokens();

	/**
	 * Retrieves the list of all {@link RevocationToken}s present in the Timestamp
	 * 
	 * NOTE: Applicable only for CAdES revocation source
	 * 
	 * @return list of {@link RevocationToken}s
	 */
	List<T> getTimestampRevocationValuesTokens();

}
