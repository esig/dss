package eu.europa.esig.dss.pdf.encryption;

import java.security.SecureRandom;

public interface SecureRandomProvider {
	
	/**
	 * Gets SecureRandom instance
	 * 
	 * @return {@link SecureRandom}
	 */
	SecureRandom getSecureRandom();

}
