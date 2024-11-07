/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.spi.x509;

import eu.europa.esig.dss.model.DSSException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;

/**
 * Checks signature integrity among a provided list of signing certificate candidates
 *
 */
public abstract class SignatureIntegrityValidator {

	private static final Logger LOG = LoggerFactory.getLogger(SignatureIntegrityValidator.class);

	/** The list of errors occurred during the signature integrity validation */
	private List<String> errorMessages = null;

	/**
	 * Default constructor instantiating object with null list of erros
	 */
	protected SignatureIntegrityValidator() {
		// empty
	}
	
	/**
	 * Verifies validity of a signature across a provided signing certificate candidates list
	 * NOTE: in case of a failed validation, use getErrorMessages() method after processing this method for more details
	 * 
	 * @param candidates {@link CandidatesForSigningCertificate}
	 * @return {@link CertificateValidity} if a valid signing certificate found, NULL otherwise
	 */
	public CertificateValidity validate(CandidatesForSigningCertificate candidates) {
		
		errorMessages = new ArrayList<>();
		
		if (candidates.isEmpty()) {
			errorMessages.add("There is no signing certificate within the signature or certificate pool.");
		}
		
		LOG.debug("Determining signing certificate from certificate candidates list...");
		
		// 1) Process the best found candidate
		CertificateValidity bestCandidate = candidates.getTheBestCandidate();
		if (bestCandidate != null) {
			try {
				if (isSignatureIntact(bestCandidate)) {
					return bestCandidate; // best candidate either valid or better is not available
				} else {
					errorMessages.add("Signature verification failed against the best candidate.");
				}
			} catch (DSSException e) {
				LOG.debug("Exception while probing the best candidate certificate as signing certificate: {}", e.getMessage());
				errorMessages.add("Best candidate validation failed : " + e.getMessage());
			}
		}
		
		// 2) Validate among other candidates
		CertificateValidity bestCertificateValidity = null;
		boolean coreValidity = false;
		
		int certificateNumber = 0;
		final List<CertificateValidity> certificateValidityList = candidates.getCertificateValidityList();
		for (final CertificateValidity certificateValidity : certificateValidityList) {
			if (certificateValidity == bestCandidate) {
				continue; // do not process validation twice
			}
			String errorMessagePrefix = "Certificate #" + (certificateNumber + 1) + ": ";
			try {
				if (isSignatureIntact(certificateValidity)) {
					bestCertificateValidity = certificateValidity;
					if (certificateValidity.isValid()) {
						LOG.info("Determining signing certificate from certificate candidates list succeeded : {}",
								certificateValidity.getCertificateToken().getDSSIdAsString());
						break;
					} else if (certificateValidity.getCertificateToken() != null) {
						LOG.warn("The signing certificate candidate '{}' does not match a signing certificate reference!",
								certificateValidity.getCertificateToken().getDSSIdAsString());
					}
					
				} else {
					// upon returning false, santuarioSignature (class XMLSignature) will log
					// "Signature verification failed." with WARN level.
					errorMessages.add(errorMessagePrefix + "Signature verification failed");
				}
				
			} catch (DSSException e) {
				LOG.debug("Exception while probing candidate certificate as signing certificate: {}", e.getMessage());
				errorMessages.add(errorMessagePrefix + e.getMessage());
			}
			certificateNumber++;
		}
		if (!coreValidity) {
			LOG.warn("Determining signing certificate from certificate candidates list failed: {}", errorMessages);
		}
		
		return bestCertificateValidity;
	}
	
	private boolean isSignatureIntact(CertificateValidity certificateValidity) {
		final PublicKey publicKey = certificateValidity.getPublicKey();
		if (verify(publicKey)) {
			LOG.debug("Public key matching the signature value found.");
			return true;
		} else {
			return false;
		}
	}
	
	/**
	 * Verifies if the signature has been created with the given public key
	 * 
	 * @param publicKey {@link PublicKey} to verify
	 * @return TRUE if the validation succeeded, FALSE otherwise
	 * @throws DSSException in case if an exception occurred
	 */
	protected abstract boolean verify(final PublicKey publicKey) throws DSSException;
	
	/**
	 * Returns error messages after processing of validate(candidates) method if present
	 * 
	 * @return a list of error messages
	 */
	public List<String> getErrorMessages() {
		if (errorMessages == null) {
			throw new IllegalStateException("The validate(candiates) method shall be proceeded before!");
		}
		return errorMessages;
	}

}
