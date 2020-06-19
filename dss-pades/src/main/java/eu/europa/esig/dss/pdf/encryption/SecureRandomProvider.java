package eu.europa.esig.dss.pdf.encryption;

import java.security.SecureRandom;

import eu.europa.esig.dss.model.SerializableParameters;

public interface SecureRandomProvider {
	
	/**
	 * Gets SecureRandom instance
	 * 
	 * @return {@link SecureRandom}
	 */
	SecureRandom getSecureRandom();
	
	/**
	 * Sets parameters to be used for signature/timestamp creation/extention
	 * 
	 * @param parameters
	 */
	void setParameters(SerializableParameters parameters);

}
