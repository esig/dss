/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * 
 * This file is part of the "DSS - Digital Signature Services" project.
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.model;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.model.x509.CertificateToken;

import java.io.Serializable;

/**
 * The interface defines signature parameters
 */
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
	 * Indicates whether a revocation check shall be performed before -LT level incorporation
	 * (i.e. on signing or T-level creation) for a signing certificate and a respectful certificate chain.
	 * When set to false, the revocation check is not performed.
	 * When set to true, a real-time revocation is being requested from external sources
	 * (shall be defined in CertificateVerifier) and processed according to alerts set within that CertificateVerifier.
	 * <p>
	 * Default value : false (no revocation check is performed on signature creation or T-level extension)
	 *
	 * @return if signature with a revoked certificate is allowed
	 */
	boolean isCheckCertificateRevocation();
	
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
	 * Get the encryption algorithm
	 *
	 * @return the encryption algorithm.
	 */
	EncryptionAlgorithm getEncryptionAlgorithm();

	/**
	 * Gets the signature algorithm.
	 *
	 * @return the signature algorithm
	 */
	SignatureAlgorithm getSignatureAlgorithm();

}
