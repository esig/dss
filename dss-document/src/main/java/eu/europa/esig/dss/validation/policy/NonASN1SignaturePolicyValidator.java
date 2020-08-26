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

import eu.europa.esig.dss.DomUtils;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.SignaturePolicy;

/**
 * This class covers the case of non ASN1 signature policies (eg : PDF file and its digest)
 */
public class NonASN1SignaturePolicyValidator extends AbstractSignaturePolicyValidator {

	@Override
	public boolean canValidate() {
		SignaturePolicy policy = getSignaturePolicy();
		if (policy.getPolicyContent() != null) {
			byte firstByte = DSSUtils.readFirstByte(policy.getPolicyContent());
			return !DSSASN1Utils.isASN1SequenceTag(firstByte) && !DomUtils.startsWithXmlPreamble(policy.getPolicyContent());
		}
		return false;
	}

	@Override
	public void validate() {
		setIdentified(true);

		SignaturePolicy signaturePolicy = getSignaturePolicy();
		Digest digest = signaturePolicy.getDigest();
		
		if (digest != null) {
			Digest recalculatedDigest = getComputedDigest(digest.getAlgorithm());
			if (digest.equals(recalculatedDigest)) {
				setStatus(true);
				setDigestAlgorithmsEqual(true);
			} else {
				addError("general",
						"The policy digest value (" + Utils.toBase64(digest.getValue()) + ") does not match the re-calculated digest value ("
								+ Utils.toBase64(recalculatedDigest.getValue()) + ").");
			}
			
		} else {
			addError("general", "The policy digest value is not defined.");
		}

	}
	
	@Override
	public Digest getComputedDigest(DigestAlgorithm digestAlgorithm) {
		SignaturePolicy signaturePolicy = getSignaturePolicy();
		DSSDocument policyContent = signaturePolicy.getPolicyContent();
		return DSSUtils.getDigest(digestAlgorithm, policyContent);
	}

}
