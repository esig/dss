package eu.europa.esig.dss.tsl.cache.result;

import eu.europa.esig.dss.enumerations.Indication;

/**
 * This class contains a signature validation result for a single file
 */
public class ValidationResult implements CachedResult {
	
	private Indication indication;
	
	/**
	 * Returns the signature validation result
	 * @return TRUE if the signature validation is valid, FALSE otherwise 
	 */
	public boolean isSignatureValid() {
		return Indication.TOTAL_PASSED == indication;
	}

}
