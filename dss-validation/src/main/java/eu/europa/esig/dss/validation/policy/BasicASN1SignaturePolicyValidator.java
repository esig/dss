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
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.signature.SignaturePolicyValidationResult;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.model.signature.SignaturePolicy;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;

/**
 * Default implementation, checks only the hash of the policy
 * 
 * Note : this implementation is not registered as a service to allow overriding
 * 
 * @author davyd.santos
 *
 */
public class BasicASN1SignaturePolicyValidator extends AbstractSignaturePolicyValidator {

	private static final Logger LOG = LoggerFactory.getLogger(BasicASN1SignaturePolicyValidator.class);

	/**
	 * Default constructor
	 */
	public BasicASN1SignaturePolicyValidator() {
		// empty
	}

	@Override
	public boolean canValidate(SignaturePolicy signaturePolicy) {
		if (signaturePolicy.getPolicyContent() != null) {
			byte firstByte = DSSUtils.readFirstByte(signaturePolicy.getPolicyContent());
			return DSSASN1Utils.isASN1SequenceTag(firstByte);
		}
		return false;
	}

	@Override
	public SignaturePolicyValidationResult validate(SignaturePolicy signaturePolicy) {
		SignaturePolicyValidationResult validationResult = new SignaturePolicyValidationResult();

		final DSSDocument policyContent = signaturePolicy.getPolicyContent();
		if (policyContent == null) {
			validationResult.addError(GENERAL_ERROR_KEY, "The signature policy content is not obtained.");
			return validationResult;
		}
		validationResult.setIdentified(true);

		final Digest digest = signaturePolicy.getDigest();
		if (digest == null) {
			validationResult.addError(GENERAL_ERROR_KEY, "The policy digest value is not defined.");
			return validationResult;
		}
		// valid if no errors occur
		validationResult.setDigestValid(true);

		try {
			final byte[] policyBytes = DSSUtils.toByteArray(policyContent);
			ASN1Sequence asn1Sequence = DSSASN1Utils.toASN1Primitive(policyBytes);

			if (asn1Sequence != null) {
				validationResult.setAsn1Processable(true);

				/*
				 * a) If the resulting document is based on TR 102 272 [i.2] (ESI: ASN.1 format for signature policies),
				 * use the digest value present in the SignPolicyDigest element from the resulting document.
				 * Check that the digest algorithm indicated in the SignPolicyDigestAlg from the resulting
				 * document is equal to the digest algorithm indicated in the property.
				 */

				/*
				 * b) If the resulting document is based on TR 102 038 [i.3] ((ESI) XML format for signature policies),
				 * use the digest value present in signPolicyHash element from the resulting document.
				 * Check that the digest algorithm indicated in the signPolicyHashAlg from the resulting
				 * document is equal to the digest algorithm indicated in the attribute.
				 */

				final ASN1Sequence signPolicyHashAlgObject = (ASN1Sequence) asn1Sequence.getObjectAt(0);
				final AlgorithmIdentifier signPolicyHashAlgIdentifier = AlgorithmIdentifier.getInstance(signPolicyHashAlgObject);
				DigestAlgorithm signPolicyHashAlgFromPolicy = DigestAlgorithm.forOID(signPolicyHashAlgIdentifier.getAlgorithm().getId());

				if (signPolicyHashAlgFromPolicy.equals(digest.getAlgorithm())) {
					validationResult.setDigestAlgorithmsEqual(true);

					Digest recalculatedDigest = getComputedDigest(policyContent, signPolicyHashAlgFromPolicy);
					validationResult.setDigest(recalculatedDigest);

					boolean equal = digest.equals(recalculatedDigest);
					validationResult.setDigestValid(equal);
					if (!equal) {
						validationResult.addError(GENERAL_ERROR_KEY,
								"The policy digest value (" + Utils.toBase64(digest.getValue()) + ") does not match the re-calculated digest value ("
										+ Utils.toBase64(recalculatedDigest.getValue()) + ").");
					}

					final ASN1OctetString signPolicyHash = (ASN1OctetString) asn1Sequence.getObjectAt(2);
					final byte[] policyDigestValueFromPolicy = signPolicyHash.getOctets();
					equal = Arrays.equals(digest.getValue(), policyDigestValueFromPolicy);
					validationResult.setDigestValid(equal);
					if (!equal) {
						validationResult.addError(GENERAL_ERROR_KEY, "The policy digest value (" + Utils.toBase64(digest.getValue())
								+ ") does not match the digest value from the policy file ("
								+ Utils.toBase64(policyDigestValueFromPolicy) + ").");
					}

				} else {
					validationResult.addError(GENERAL_ERROR_KEY, "The digest algorithm indicated in the SignPolicyHashAlg from the resulting document (" + signPolicyHashAlgFromPolicy
							+ ") is not equal to the digest " + "algorithm (" + digest.getAlgorithm() + ").");
					validationResult.setDigestAlgorithmsEqual(false);
					validationResult.setDigestValid(false);
				}
			}

		} catch (Exception e) {
			// When any error (communication) we just set the status to false
			validationResult.setDigestValid(false);
			validationResult.addError(GENERAL_ERROR_KEY, e.getMessage());
			// Do nothing
			LOG.warn(e.getMessage(), e);
		}

		return validationResult;
	}
	
	@Override
	public Digest getComputedDigest(DSSDocument policyDocument, DigestAlgorithm digestAlgorithm) {
		byte[] asn1SignaturePolicyDigest = DSSASN1Utils.getAsn1SignaturePolicyDigest(
				digestAlgorithm, DSSUtils.toByteArray(policyDocument));
		return new Digest(digestAlgorithm, asn1SignaturePolicyDigest);
	}

}
