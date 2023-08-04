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

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.SignaturePolicy;

import java.io.IOException;
import java.io.InputStream;

/**
 * This class covers the case of non ASN1 signature policies (e.g. : PDF file and its digest)
 */
public class NonASN1SignaturePolicyValidator extends AbstractSignaturePolicyValidator {

	/**
	 * Default constructor
	 */
	public NonASN1SignaturePolicyValidator() {
		// empty
	}

	@Override
	public boolean canValidate(SignaturePolicy signaturePolicy) {
		DSSDocument policyContent = signaturePolicy.getPolicyContent();
		if (policyContent != null) {
			byte firstByte = DSSUtils.readFirstByte(policyContent);
			// non ASN1 nor XML policy
			return !DSSASN1Utils.isASN1SequenceTag(firstByte) && '<' != firstByte && !startsWithXmlBom(policyContent);
		}
		return false;
	}

	private boolean startsWithXmlBom(DSSDocument policyContent) {
		try (InputStream is = policyContent.openStream()) {
			return Utils.startsWith(is, new byte[] { -17, -69, -65, '<' });
		} catch (IOException e) {
			throw new DSSException("Cannot read the InputStream!", e);
		}
	}

	@Override
	public SignaturePolicyValidationResult validate(SignaturePolicy signaturePolicy) {
		SignaturePolicyValidationResult validationResult = new SignaturePolicyValidationResult();

		DSSDocument policyContent = signaturePolicy.getPolicyContent();
		if (policyContent == null) {
			validationResult.addError(GENERAL_ERROR_KEY, "The signature policy content is not obtained.");
			return validationResult;
		}
		validationResult.setIdentified(true);

		Digest digest = signaturePolicy.getDigest();
		if (digest == null) {
			validationResult.addError(GENERAL_ERROR_KEY, "The policy digest value is not defined.");
			return validationResult;
		}
		validationResult.setDigestAlgorithmsEqual(true);

		Digest recalculatedDigest = getComputedDigest(signaturePolicy.getPolicyContent(), digest.getAlgorithm());
		validationResult.setDigest(recalculatedDigest);

		if (digest.equals(recalculatedDigest)) {
			validationResult.setDigestValid(true);
			validationResult.setDigestAlgorithmsEqual(true);
		} else {
			validationResult.addError(GENERAL_ERROR_KEY,
					"The policy digest value (" + Utils.toBase64(digest.getValue()) + ") does not match the re-calculated digest value ("
							+ Utils.toBase64(recalculatedDigest.getValue()) + ").");
		}

		return validationResult;
	}

}
