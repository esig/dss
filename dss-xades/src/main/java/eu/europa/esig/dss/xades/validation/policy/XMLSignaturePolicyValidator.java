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
package eu.europa.esig.dss.xades.validation.policy;

import eu.europa.esig.dss.model.signature.SignaturePolicyValidationResult;
import eu.europa.esig.dss.xades.validation.XAdESSignaturePolicy;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.signature.XMLSignatureInput;
import org.apache.xml.security.transforms.Transforms;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import eu.europa.esig.dss.xml.utils.DomUtils;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.model.signature.SignaturePolicy;
import eu.europa.esig.dss.validation.policy.AbstractSignaturePolicyValidator;

import java.io.IOException;

/**
 * Validates an XML Signature Policy
 */
public class XMLSignaturePolicyValidator extends AbstractSignaturePolicyValidator {

	private static final Logger LOG = LoggerFactory.getLogger(XMLSignaturePolicyValidator.class);

	/** The error key to be used for XML processing related issues */
	protected static final String XML_ERROR_KEY = "xmlProcessing";

	/**
	 * Default constructor
	 */
	public XMLSignaturePolicyValidator() {
		// empty
	}

	@Override
	public boolean canValidate(SignaturePolicy signaturePolicy) {
		if (signaturePolicy.getPolicyContent() != null) {
			return DomUtils.startsWithXmlPreamble(signaturePolicy.getPolicyContent());
		}
		return false;
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

		Digest recalculatedDigest = null;
		Element transforms = null;
		if (signaturePolicy instanceof XAdESSignaturePolicy) {
			XAdESSignaturePolicy xadesSignaturePolicy = (XAdESSignaturePolicy) signaturePolicy;
			transforms = xadesSignaturePolicy.getTransforms();
		}

		if (transforms != null) {
			try {
				recalculatedDigest = getDigestAfterTransforms(signaturePolicy.getPolicyContent(),
						digest.getAlgorithm(), transforms);
			} catch (Exception e) {
				String errorMessage = String.format("Unable to perform transforms on an XML Policy. Reason : %s", e.getMessage());
				LOG.warn(errorMessage, e);
				validationResult.addError(XML_ERROR_KEY, errorMessage);
			}
		} else {
			recalculatedDigest = getComputedDigest(signaturePolicy.getPolicyContent(), digest.getAlgorithm());
		}
		validationResult.setDigest(recalculatedDigest);

		if (recalculatedDigest != null) {
			if (digest.equals(recalculatedDigest)) {
				validationResult.setDigestValid(true);
			} else {
				validationResult.addError(GENERAL_ERROR_KEY,
						"The policy digest value (" + Utils.toBase64(digest.getValue()) + ") does not match the re-calculated digest value ("
								+ Utils.toBase64(recalculatedDigest.getValue()) + ").");
			}
		}

		return validationResult;
	}

	/**
	 * Computes Digests after processing of given {@code transformsElement}
	 *
	 * @param policyDocument {@link DSSDocument} policy content
	 * @param digestAlgorithm {@link DigestAlgorithm} to use to calculate digest
	 * @param transformsElement {@link Element} ds:Transforms element
	 * @return {@link Digest} computed on octets obtained after performing of transforms
	 * @throws XMLSecurityException if an exception occurs during transforms processing
	 * @throws IOException if an exception occurs during transforms processing result reading
	 */
	public Digest getDigestAfterTransforms(DSSDocument policyDocument, DigestAlgorithm digestAlgorithm, Element transformsElement)
			throws XMLSecurityException, IOException {
		if (transformsElement != null) {
			Transforms transforms = new Transforms(transformsElement, "");

			Document document = DomUtils.buildDOM(policyDocument);
			XMLSignatureInput xmlSignatureInput = new XMLSignatureInput(document);

			XMLSignatureInput xmlSignatureInputOut = transforms.performTransforms(xmlSignatureInput);
			byte[] bytesToBeDigested = xmlSignatureInputOut.getBytes();
			return new Digest(digestAlgorithm, DSSUtils.digest(digestAlgorithm, bytesToBeDigested));
		} else {
			return getComputedDigest(policyDocument, digestAlgorithm);
		}
	}

}
