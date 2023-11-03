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
package eu.europa.esig.dss.xades.signature;

import eu.europa.esig.dss.xml.utils.DomUtils;
import eu.europa.esig.dss.exception.IllegalInputException;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.SignaturePolicyStore;
import eu.europa.esig.dss.model.SpDocSpecification;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.policy.SignaturePolicyValidator;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.xades.definition.xades141.XAdES141Attribute;
import eu.europa.esig.xades.definition.xades141.XAdES141Element;
import eu.europa.esig.dss.xades.validation.XAdESSignature;
import eu.europa.esig.dss.xades.validation.XAdESSignaturePolicy;
import eu.europa.esig.dss.xades.validation.XMLDocumentValidator;
import eu.europa.esig.dss.xades.validation.policy.XMLSignaturePolicyValidator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import java.util.Objects;

/**
 * Builds a XAdES SignaturePolicyStore
 *
 */
public class SignaturePolicyStoreBuilder extends ExtensionBuilder {

	private static final Logger LOG = LoggerFactory.getLogger(SignaturePolicyStoreBuilder.class);

	/**
	 * Default constructor
	 */
	public SignaturePolicyStoreBuilder() {
		// empty
	}

	/**
	 * Adds a signaturePolicyStore to all signatures inside the document, matching the incorporated signature policy
	 *
	 * @param signatureDocument {@link DSSDocument} containing signatures to add signature policy store into
	 * @param signaturePolicyStore {@link SignaturePolicyStore} to add
	 * @return {@link DSSDocument} with signaturePolicyStore
	 */
	public DSSDocument addSignaturePolicyStore(DSSDocument signatureDocument, SignaturePolicyStore signaturePolicyStore) {
		Objects.requireNonNull(signatureDocument, "Signature document must be provided!");
		assertConfigurationValid(signaturePolicyStore);

		final XMLDocumentValidator documentValidator = initDocumentValidator(signatureDocument);

		boolean signaturePolicyStoreAdded = false;
		for (AdvancedSignature signature : documentValidator.getSignatures()) {
			boolean added = addSignaturePolicyStoreIfDigestMatch((XAdESSignature) signature, documentDom, signaturePolicyStore);
			signaturePolicyStoreAdded = signaturePolicyStoreAdded || added;
		}
		if (!signaturePolicyStoreAdded) {
			throw new IllegalInputException("The process did not find a signature to add SignaturePolicyStore!");
		}

		return createXmlDocument();
	}

	/**
	 * Adds a signaturePolicyStore to a signature with the given {@code signatureId},
	 * if the signature policy identifier matches the policy provided within {@code SignaturePolicyStore}
	 *
	 * @param signatureDocument {@link DSSDocument} containing signatures to add signature policy store into
	 * @param signaturePolicyStore {@link SignaturePolicyStore} to add
	 * @param signatureId {@link String} Id of a signature to add SignaturePolicyStore for
	 * @return {@link DSSDocument} with signaturePolicyStore
	 */
	public DSSDocument addSignaturePolicyStore(DSSDocument signatureDocument, SignaturePolicyStore signaturePolicyStore,
											   String signatureId) {
		Objects.requireNonNull(signatureDocument, "Signature document must be provided!");
		assertConfigurationValid(signaturePolicyStore);

		final XMLDocumentValidator documentValidator = initDocumentValidator(signatureDocument);
		AdvancedSignature signature = documentValidator.getSignatureById(signatureId);
		if (signature == null) {
			throw new IllegalInputException(String.format("Unable to find a signature with Id : %s!", signatureId));
		}
		boolean added = addSignaturePolicyStoreIfDigestMatch((XAdESSignature) signature, documentDom, signaturePolicyStore);
		if (!added) {
			throw new IllegalInputException(String.format(
					"The process was not able to add SignaturePolicyStore to a signature with Id : %s!", signatureId));
		}

		return createXmlDocument();
	}

	private XMLDocumentValidator initDocumentValidator(DSSDocument document) {
		params = new XAdESSignatureParameters();

		documentValidator = new XMLDocumentValidator(document);
		documentDom = documentValidator.getRootElement();

		return documentValidator;
	}

	/**
	 * This method adds {@code SignaturePolicyStore} to a {@code documentDom} if required
	 *
	 * @param xadesSignature {@link XAdESSignature} signature to add {@link SignaturePolicyStore}
	 * @param documentDom {@link Document} root DOM of the signature document
	 * @param signaturePolicyStore {@link SignaturePolicyStore} to be added
	 * @return TRUE if the signaturePolicyStore has been added for the particular signature, FALSE otherwise
	 */
	protected boolean addSignaturePolicyStoreIfDigestMatch(XAdESSignature xadesSignature, Document documentDom,
														SignaturePolicyStore signaturePolicyStore) {
		xadesSignature = initializeSignatureBuilder(xadesSignature);

		ensureUnsignedProperties();
		ensureUnsignedSignatureProperties();

		if (checkDigest(xadesSignature, signaturePolicyStore)) {
			Element signaturePolicyStoreElement = DomUtils.addElement(documentDom, unsignedSignaturePropertiesDom, getXades141Namespace(),
					XAdES141Element.SIGNATURE_POLICY_STORE);

			if (signaturePolicyStore.getId() != null) {
				signaturePolicyStoreElement.setAttribute(XAdES141Attribute.ID.getAttributeName(), signaturePolicyStore.getId());
			}

			SpDocSpecification spDocSpecification = signaturePolicyStore.getSpDocSpecification();
			incorporateSPDocSpecification(signaturePolicyStoreElement, spDocSpecification);

			DSSDocument signaturePolicyContent = signaturePolicyStore.getSignaturePolicyContent();
			if (signaturePolicyContent != null) {
				Element policyDocElement = DomUtils.addElement(documentDom, signaturePolicyStoreElement, getXades141Namespace(),
						XAdES141Element.SIGNATURE_POLICY_DOCUMENT);

				DomUtils.setTextNode(documentDom, policyDocElement,
						Utils.toBase64(DSSUtils.toByteArray(signaturePolicyContent)));
			}

			String sigPolDocLocalURI = signaturePolicyStore.getSigPolDocLocalURI();
			if (Utils.isStringNotEmpty(sigPolDocLocalURI)) {
				DomUtils.addTextElement(documentDom, signaturePolicyStoreElement, getXades141Namespace(),
						XAdES141Element.SIG_POL_DOC_LOCAL_URI, sigPolDocLocalURI);
			}

			return true;
		}

		return false;
	}

	/**
	 * This method verifies if the digests computed in the provided {@code SignaturePolicyStore} match
	 * the digest defined in the incorporated signature policy identifier
	 *
	 * @param xadesSignature {@link XAdESSignature} to check signature policy identifier
	 * @param signaturePolicyStore {@link SignaturePolicyStore} to be incorporated
	 * @return TRUE if the digest match and {@link SignaturePolicyStore} can be embedded, FALSE otherwise
	 */
	protected boolean checkDigest(XAdESSignature xadesSignature, SignaturePolicyStore signaturePolicyStore) {
		final String currentSignatureId = xadesSignature.getDAIdentifier();

		final XAdESSignaturePolicy signaturePolicy = xadesSignature.getSignaturePolicy();
		if (signaturePolicy == null) {
			LOG.warn("No defined SignaturePolicyIdentifier for signature with Id : {}", currentSignatureId);
			return false;
		}
		final Digest digest = signaturePolicy.getDigest();
		if (digest == null) {
			LOG.warn("No defined digest for signature with Id : {}", currentSignatureId);
			return false;
		}

		DSSDocument signaturePolicyContent = signaturePolicyStore.getSignaturePolicyContent();
		if (signaturePolicyContent == null) {
			LOG.info("No policy document has been provided. Digests are not checked!");
			return true;
		}
		signaturePolicy.setPolicyContent(signaturePolicyContent);

		Digest computedDigest;
		try {
			SignaturePolicyValidator validator = documentValidator.getSignaturePolicyValidatorLoader().loadValidator(signaturePolicy);
			if (validator instanceof XMLSignaturePolicyValidator) {
				XMLSignaturePolicyValidator xmlSignaturePolicyValidator = (XMLSignaturePolicyValidator) validator;
				computedDigest = xmlSignaturePolicyValidator.getDigestAfterTransforms(signaturePolicyContent,
						digest.getAlgorithm(), signaturePolicy.getTransforms());
			} else {
				computedDigest = validator.getComputedDigest(signaturePolicyStore.getSignaturePolicyContent(), digest.getAlgorithm());
			}

		} catch (Exception e) {
			throw new DSSException(String.format("Unable to compute digest for a SignaturePolicyStore. " +
					"Reason : %s", e.getMessage()), e);
		}

		boolean digestMatch = digest.equals(computedDigest);
		if (!digestMatch) {
			LOG.warn("Signature policy's digest {} doesn't match the digest extracted from document {} for signature with Id : {}",
					computedDigest, digest, currentSignatureId);
		}
		return digestMatch;
	}

	private void assertConfigurationValid(SignaturePolicyStore signaturePolicyStore) {
		Objects.requireNonNull(signaturePolicyStore, "SignaturePolicyStore must be provided");
		Objects.requireNonNull(signaturePolicyStore.getSpDocSpecification(), "SpDocSpecification must be provided");
		Objects.requireNonNull(signaturePolicyStore.getSpDocSpecification().getId(), "ID (OID or URI) for SpDocSpecification must be provided");

		boolean signaturePolicyContentPresent = signaturePolicyStore.getSignaturePolicyContent() != null;
		boolean sigPolDocLocalURIPresent = signaturePolicyStore.getSigPolDocLocalURI() != null;
		if (!(signaturePolicyContentPresent ^ sigPolDocLocalURIPresent)) {
			throw new IllegalArgumentException("SignaturePolicyStore shall contain either " +
					"SignaturePolicyContent document or sigPolDocLocalURI!");
		}
	}

}
