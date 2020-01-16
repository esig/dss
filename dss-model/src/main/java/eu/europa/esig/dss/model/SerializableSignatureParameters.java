package eu.europa.esig.dss.model;

import java.io.Serializable;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.MaskGenerationFunction;
import eu.europa.esig.dss.model.x509.CertificateToken;

public interface SerializableSignatureParameters extends Serializable {
	
	/**
	 * Get the signing certificate
	 *
	 * @return the signing certificate
	 */
	CertificateToken getSigningCertificate();
	
	/**
	 * Indicates if it is possible to generate ToBeSigned data without the signing certificate.
	 * The default values is false.
	 *
	 * @return true if signing certificate is not required when generating ToBeSigned data.
	 */
	boolean isGenerateTBSWithoutCertificate();
	
	/**
	 * Indicates if it is possible to sign with an expired certificate. The default value is false.
	 *
	 * @return true if signature with an expired certificate is allowed
	 */
	boolean isSignWithExpiredCertificate();
	
	/**
	 * Get Baseline B parameters (signed properties)
	 * 
	 * @return the Baseline B parameters
	 */
	BLevelParameters bLevel();
	
	/**
	 * Get the digest algorithm
	 * 
	 * @return the digest algorithm
	 */
	DigestAlgorithm getDigestAlgorithm();
	
	/**
	 * Returns the mask generation function
	 * 
	 * @return {@link MaskGenerationFunction}
	 */
	MaskGenerationFunction getMaskGenerationFunction();

}
