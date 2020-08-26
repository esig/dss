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
package eu.europa.esig.dss.validation.policy;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.SignaturePolicy;

public interface SignaturePolicyValidator {

	/**
	 * Sets the {@code AdvancedSignature} containing a {@code SignaturePolicy} to validate
	 * 
	 * NOTE: Deprecated, please use:
	 * {@code 
	 * 		SignaturePolicy signaturePolicy = signature.getSignaturePolicy();
	 * 		SignaturePolicyValidator.setSignaturePolicy(signaturePolicy);
	 * }
	 * 
	 * @param signature {@link AdvancedSignature}
	 */
	@Deprecated
	void setSignature(AdvancedSignature signature);
	
	/**
	 * Sets {@code SignaturePolicy} to validate
	 * 
	 * @param signaturePolicy {@link SignaturePolicy}
	 */
	void setSignaturePolicy(SignaturePolicy signaturePolicy);

	/**
	 * Checks if the SignaturePolicy can be validated
	 * 
	 * @return TRUE if the {@code SignaturePolicy} can be validated, FALSE otherwise
	 */
	boolean canValidate();

	/**
	 * Runs the validation
	 */
	void validate();

	/* ===== Validation results ===== */
	
	/**
	 * Gets if the {@code SignaturePolicy} has been identified
	 * 
	 * @return TRUE if the signature policy has been identified, FALSE otherwise
	 */
	boolean isIdentified();

	/**
	 * Gets if the {@code SignaturePolicy} is valid
	 * 
	 * @return TRUE if the signature policy is valid, FALSE otherwise
	 */
	boolean isStatus();

	/**
	 * Gets if the {@code SignaturePolicy} is ASN.1 processable
	 * 
	 * @return TRUE if the signature policy is ASN.1, FALSE otherwise
	 */
	boolean isAsn1Processable();

	/**
	 * Gets if digest value incorporated in the signature equals to the digest of the SignaturePolicy content
	 * 
	 * @return TRUE if the digests equal, FALSE otherwise
	 */
	boolean isDigestAlgorithmsEqual();

	/**
	 * Returns a list of errors occurred during the {@code SignaturePolicy} validation process when applicable
	 * 
	 * @return a list of {@link String} error messages
	 */
	String getProcessingErrors();
	
	/**
	 * Returns {@code Digest} on the computed SignaturePolicy's content
	 * 
	 * @param digestAlgorithm {@link DigestAlgorithm} to use
	 * @return {@link Digest}
	 */
	Digest getComputedDigest(DigestAlgorithm digestAlgorithm);

}
