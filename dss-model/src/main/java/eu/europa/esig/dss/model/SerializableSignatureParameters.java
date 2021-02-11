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
import eu.europa.esig.dss.enumerations.MaskGenerationFunction;
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
	 * Indicates if it is possible to sign with an expired certificate. The default value is false.
	 *
	 * @return true if signature with an expired certificate is allowed
	 */
	boolean isSignWithExpiredCertificate();

	/**
	 * Indicates if it is possible to sign with a not yet valid certificate. The default value is false.
	 *
	 * @return true if signature with a not yet valid certificate is allowed
	 */
	boolean isSignWithNotYetValidCertificate();
	
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
