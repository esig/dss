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
package eu.europa.esig.dss.diagnostic;

import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.MaskGenerationFunction;

import java.util.List;

/**
 * Interface providing user-friendly API for dealing with JAXB objects from a DiagnosticData
 *
 */
public interface TokenProxy {

	/**
	 * Returns the unique identifier of the object
	 *
	 * @return {@link String} id
	 */
	String getId();

	/**
	 * Returns if the signatureValue of the token is valid against the identifier signing certificate's public key
	 *
	 * @return TRUE if the signatureValue is intact, FALSE otherwise
	 */
	boolean isSignatureIntact();

	/**
	 * Returns if the signature and all signed data is cryptographically correct
	 *
	 * @return TRUE if the signature is cryptographically valid, FALSE otherwise
	 */
	boolean isSignatureValid();

	/**
	 * Returns the DigestAlgorithm used to create the signatureValue
	 *
	 * @return {@link DigestAlgorithm}
	 */
	DigestAlgorithm getDigestAlgorithm();

	/**
	 * Returns the EncryptionAlgorithm used to create the signature
	 *
	 * @return {@link EncryptionAlgorithm}
	 */
	EncryptionAlgorithm getEncryptionAlgorithm();

	/**
	 * Returns the MaskGenerationFunction if has been used on signature creation
	 *
	 * @return {@link MaskGenerationFunction}
	 */
	MaskGenerationFunction getMaskGenerationFunction();

	/**
	 * Returns the length of the private key used to create the signatureValue of the token
	 *
	 * @return {link String} key length
	 */
	String getKeyLengthUsedToSignThisToken();

	/**
	 * Returns the signing certificate of the token if identified
	 *
	 * @return {@link CertificateWrapper}
	 */
	CertificateWrapper getSigningCertificate();

	/**
	 * Returns if a reference to the SigningCertificate is present within the token (used for signatures and timestamps)
	 *
	 * @return TRUE if a reference to the SigningCertificate is present, FALSE otherwise
	 */
	boolean isSigningCertificateReferencePresent();

	/**
	 * Returns if the reference to the signing certificate is unique and present only once
	 *
	 * @return TRUE if the reference to the signing certificate is unique, FALSE otherwise
	 */
	boolean isSigningCertificateReferenceUnique();

	/**
	 * Returns the reference to the signing certificate present within the token (for signature or timestamp)
	 *
	 * @return {@link CertificateRefWrapper} reference to the signing certificate
	 */
	CertificateRefWrapper getSigningCertificateReference();

	/**
	 * Returns a list of all references to the signing certificate present within the token (for signature or timestamp)
	 *
	 * @return a list of {@link CertificateRefWrapper} references to the signing certificate
	 */
	List<CertificateRefWrapper> getSigningCertificateReferences();

	/**
	 * Returns the public key binaries of the signing certificate
	 *
	 * @return public key of the signing certificate
	 */
	byte[] getSigningCertificatePublicKey();

	/**
	 * Returns the certificate chain
	 *
	 * @return a list of {@link CertificateWrapper} representing the certificate chain
	 */
	List<CertificateWrapper> getCertificateChain();

	/**
	 * Returns of the certificate chain is trusted
	 *
	 * @return TRUE if the certificate chain is trusted, FALSE otherwise
	 */
	boolean isTrustedChain();

	/**
	 * Returns a list of DigestMatchers used in the validation process for a signature or timestamp
	 *
	 * @return a list of {@link XmlDigestMatcher}s
	 */
	List<XmlDigestMatcher> getDigestMatchers();

	/**
	 * Returns FoundCertificatesProxy to access embedded certificates
	 * 
	 * @return {@link FoundCertificatesProxy}
	 */
	FoundCertificatesProxy foundCertificates();

	/**
	 * Returns FoundRevocationsProxy to access embedded revocation data
	 * 
	 * @return {@link FoundRevocationsProxy}
	 */
	FoundRevocationsProxy foundRevocations();

}
