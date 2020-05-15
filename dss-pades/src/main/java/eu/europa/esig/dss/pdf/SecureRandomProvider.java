package eu.europa.esig.dss.pdf;

import java.io.IOException;
import java.security.SecureRandom;

import eu.europa.esig.dss.model.SerializableParameters;

public interface SecureRandomProvider {
	
	/**
	 * Returns SecureRandom instance for the given parameters
	 * 
	 * @param parameters {@link SerializableParameters}
	 * @return {@link SecureRandom}
	 * @throws {@link IOException} if an exception occurs
	 */
	SecureRandom getSecureRandom(SerializableParameters parameters) throws IOException;

}
