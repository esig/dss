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
package eu.europa.esig.dss.validation;

import java.util.Arrays;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSASN1Utils;
import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.x509.SignaturePolicy;

/**
 * Default implementation, checks only the hash of the policy
 * 
 * Note : this implementation is not registered as a service to allow overriding
 * 
 * @author davyd.santos
 *
 */
public class BasicASNSignaturePolicyValidator extends AbstractSignaturePolicyValidator {

	private static final Logger LOG = LoggerFactory.getLogger(BasicASNSignaturePolicyValidator.class);

	@Override
	public void validate() {
		SignaturePolicy signaturePolicy = getSignaturePolicy();

		final DSSDocument policyContent = signaturePolicy.getPolicyContent();
		byte[] policyBytes = DSSUtils.toByteArray(policyContent);
		final byte[] digestValue = signaturePolicy.getDigestValue();
		final DigestAlgorithm signPolicyHashAlgFromSignature = signaturePolicy.getDigestAlgorithm();

		setStatus(true);
		setIdentified(true);

		try {
			ASN1Sequence asn1Sequence = DSSASN1Utils.toASN1Primitive(policyBytes);

			if (asn1Sequence != null) {
				setAsn1Processable(true);

				/**
				 * a) If the resulting document is based on TR 102 272 [i.2] (ESI: ASN.1 format for signature policies),
				 * use the digest value present in the
				 * SignPolicyDigest element from the resulting document. Check that the digest algorithm indicated in
				 * the SignPolicyDigestAlg from the resulting
				 * document is equal to the digest algorithm indicated in the property.
				 */

				final ASN1Sequence signPolicyHashAlgObject = (ASN1Sequence) asn1Sequence.getObjectAt(0);
				final AlgorithmIdentifier signPolicyHashAlgIdentifier = AlgorithmIdentifier.getInstance(signPolicyHashAlgObject);
				DigestAlgorithm signPolicyHashAlgFromPolicy = DigestAlgorithm.forOID(signPolicyHashAlgIdentifier.getAlgorithm().getId());

				/**
				 * b) If the resulting document is based on TR 102 038 [i.3] ((ESI) XML format for signature policies),
				 * use the digest value present in
				 * signPolicyHash element from the resulting document. Check that the digest algorithm indicated in the
				 * signPolicyHashAlg from the resulting
				 * document is equal to the digest algorithm indicated in the attribute.
				 */

				/**
				 * The use of a zero-sigPolicyHash value is to ensure backwards compatibility with earlier versions of
				 * the current document. If sigPolicyHash is
				 * zero, then the hash value should not be checked against the calculated hash value of the signature
				 * policy.
				 */
				if (!signPolicyHashAlgFromPolicy.equals(signPolicyHashAlgFromSignature)) {
					addError("general", "The digest algorithm indicated in the SignPolicyHashAlg from the resulting document (" + signPolicyHashAlgFromPolicy
							+ ") is not equal to the digest " + "algorithm (" + signPolicyHashAlgFromSignature + ").");
					setDigestAlgorithmsEqual(false);
					setStatus(false);
					return;
				} else {
					setDigestAlgorithmsEqual(true);
				}

				byte[] recalculatedDigestValue = DSSASN1Utils.getAsn1SignaturePolicyDigest(signPolicyHashAlgFromPolicy, policyBytes);

				boolean equal = Arrays.equals(digestValue, recalculatedDigestValue);
				setStatus(equal);
				if (!equal) {
					addError("general",
							"The policy digest value (" + Utils.toBase64(digestValue) + ") does not match the re-calculated digest value ("
									+ Utils.toBase64(recalculatedDigestValue) + ").");
					return;
				}

				final ASN1OctetString signPolicyHash = (ASN1OctetString) asn1Sequence.getObjectAt(2);
				final byte[] policyDigestValueFromPolicy = signPolicyHash.getOctets();
				equal = Arrays.equals(digestValue, policyDigestValueFromPolicy);
				setStatus(equal);
				if (!equal) {
					addError("general", "The policy digest value (" + Utils.toBase64(digestValue) + ") does not match the digest value from the policy file ("
							+ Utils.toBase64(policyDigestValueFromPolicy) + ").");
				}
			}

		} catch (Exception e) {
			// When any error (communication) we just set the status to false
			setStatus(false);
			addError("general", e.getMessage());
			// Do nothing
			LOG.warn(e.getMessage(), e);
		}
	}

	@Override
	public boolean canValidate() {
		SignaturePolicy policy = getSignaturePolicy();
		if (policy.getPolicyContent() != null) {
			byte firstByte = DSSUtils.readFirstByte(policy.getPolicyContent());
			return DSSASN1Utils.isASN1SequenceTag(firstByte);
		}
		return false;
	}

}
