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

import eu.europa.esig.dss.DomUtils;
import eu.europa.esig.dss.definition.xmldsig.XMLDSigAttribute;
import eu.europa.esig.dss.definition.xmldsig.XMLDSigElement;
import eu.europa.esig.dss.definition.xmldsig.XMLDSigPaths;
import eu.europa.esig.dss.enumerations.TimestampedObjectType;
import eu.europa.esig.dss.exception.IllegalInputException;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.xades.DSSXMLUtils;
import eu.europa.esig.dss.xades.reference.CanonicalizationTransform;
import eu.europa.esig.dss.xades.reference.DSSReference;
import eu.europa.esig.dss.xades.reference.DSSTransform;
import eu.europa.esig.dss.xades.validation.XAdESSignature;
import eu.europa.esig.dss.xades.validation.XMLDocumentValidator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import java.util.Collections;
import java.util.List;
import java.util.Objects;

import static javax.xml.crypto.dsig.XMLSignature.XMLNS;

/**
 * The XAdES CounterSignatureBuilder used to create a counter signature 
 * signing a SignatureValue of a parent signature
 *
 */
public class CounterSignatureBuilder extends ExtensionBuilder {

	private static final Logger LOG = LoggerFactory.getLogger(CounterSignatureBuilder.class);

	/** The default prefix for a counter signature id */
	private final static String COUNTER_SIGNATURE_PREFIX = "CS-";

	/**
	 * Default constructor
	 *
	 * @param certificateVerifier {@link CertificateVerifier}
	 */
	protected CounterSignatureBuilder(CertificateVerifier certificateVerifier) {
		super(certificateVerifier);
	}
	
	/**
	 * Extract a canonicalized SignatureValue element from the provided XAdES signature
	 * 
	 * @param signatureDocument {@link DSSDocument} to be counter-signed
	 * @param parameters {@link XAdESCounterSignatureParameters}
	 * @return {@link DSSDocument} extracted and canonicalized SignatureValue
	 */
	public DSSDocument getCanonicalizedSignatureValue(DSSDocument signatureDocument, XAdESCounterSignatureParameters parameters) {
		params = parameters;

		documentValidator = new XMLDocumentValidator(signatureDocument);
		documentDom = documentValidator.getRootElement();

		xadesSignature = extractSignatureById(parameters);

		Element signatureValueElement = getSignatureValueElement(xadesSignature);
		byte[] canonicalizedSignatureValue = DSSXMLUtils.canonicalizeSubtree(
				parameters.getCounterSignatureCanonicalizationMethod(), signatureValueElement);
		
		if (LOG.isTraceEnabled()) {
			LOG.trace("Canonicalized SignatureValue:");
			LOG.trace(new String(canonicalizedSignatureValue));
		}
		
		return new InMemoryDocument(canonicalizedSignatureValue);
	}
	
	/**
	 * The method builds a {@link DSSReference} for a SignatureValue to counter sign
	 * 
	 * @param signatureDocument {@link DSSDocument} document containing a signature being counter signed
	 * @param parameters {@link XAdESCounterSignatureParameters}
	 * @return {@link DSSReference} for incorporation into a counter signature
	 */
	public DSSReference buildCounterSignatureDSSReference(DSSDocument signatureDocument, XAdESCounterSignatureParameters parameters) {
		documentValidator = new XMLDocumentValidator(signatureDocument);
		documentDom = documentValidator.getRootElement();

		xadesSignature = extractSignatureById(parameters);
		initializeSignatureBuilder(xadesSignature);
		
		DSSReference reference = new DSSReference();
		byte[] signatureElementBinaries = DSSXMLUtils.serializeNode(xadesSignature.getSignatureElement());
		reference.setContents(new InMemoryDocument(signatureElementBinaries));
		reference.setDigestMethodAlgorithm(getReferenceDigestAlgorithmOrDefault(parameters));
		reference.setType(xadesPaths.getCounterSignatureUri());

		String signatureValueId = xadesSignature.getSignatureValueId();
		if (Utils.isStringNotEmpty(signatureValueId)) {
			reference.setUri("#" + signatureValueId);
			DSSTransform transform = new CanonicalizationTransform(parameters.getCounterSignatureCanonicalizationMethod());
			reference.setTransforms(Collections.singletonList(transform));
			
		} else {
			// TODO : build an XPath ???
			throw new IllegalInputException(String.format(
					"The signature with Id '%s' does not have an Id for a SignatureValue element! " +
							"Unable to counter sign.", parameters.getSignatureIdToCounterSign()));
		}
		return reference;
	}
	
	/**
	 * Embeds and returns the embedded counter signature into the UnsignedProperties of original XAdES signature
	 * 
	 * @param signatureDocument {@link DSSDocument} the original document containing the signature to be counter signed
	 * @param counterSignature {@link DSSDocument} the counter signature
	 * @param parameters {@link XAdESCounterSignatureParameters}
	 * @return {@link DSSDocument} original signature enveloping the {@code counterSignature} into the UnsignedProperties
	 */
	public DSSDocument buildEmbeddedCounterSignature(DSSDocument signatureDocument, DSSDocument counterSignature, 
			XAdESCounterSignatureParameters parameters) {
		params = parameters;

		documentValidator = new XMLDocumentValidator(signatureDocument);
		documentDom = documentValidator.getRootElement();

		xadesSignature = extractSignatureById(parameters);
		initializeSignatureBuilder(xadesSignature);
		
		Element levelBUnsignedProperties = (Element) unsignedSignaturePropertiesDom.cloneNode(true);
		
		incorporateCounterSignature(counterSignature);

		unsignedSignaturePropertiesDom = indentIfPrettyPrint(unsignedSignaturePropertiesDom, levelBUnsignedProperties);
		
		return createXmlDocument();
	}
	
	private void incorporateCounterSignature(DSSDocument counterSignature) {
		Document counterSignatureDom = DomUtils.buildDOM(counterSignature);
		
		final NodeList signatureNodeList = counterSignatureDom.getElementsByTagNameNS(XMLNS, XMLDSigElement.SIGNATURE.getTagName());
		if (signatureNodeList.getLength() != 1) {
			throw new IllegalInputException(String.format("The counterSignature document shall have one counter signature, when %s signatures found!",
					signatureNodeList.getLength()));
		}
		
		Element signatureElement = (Element) signatureNodeList.item(0);
		Node adopted = documentDom.importNode(signatureElement, true);
		
		Element counterSignatureElement = DomUtils.addElement(documentDom, unsignedSignaturePropertiesDom, 
				getXadesNamespace(), getCurrentXAdESElements().getElementCounterSignature());
		counterSignatureElement.setAttribute(XMLDSigAttribute.ID.getAttributeName(), COUNTER_SIGNATURE_PREFIX + params.getDeterministicId());
		counterSignatureElement.appendChild(adopted);
	}
	
	private XAdESSignature extractSignatureById(XAdESCounterSignatureParameters parameters) {
		Objects.requireNonNull(parameters.getSignatureIdToCounterSign(), "The Id of a signature to be counter signed shall be defined! "
					+ "Please use SerializableCounterSignatureParameters.setSignatureIdToCounterSign(signatureId) method.");

		List<AdvancedSignature> signatures = documentValidator.getSignatures();
		for (AdvancedSignature signature : signatures) {
			XAdESSignature signatureById = getSignatureOrItsCounterSignatureById((XAdESSignature) signature, parameters.getSignatureIdToCounterSign());
			if (signatureById != null) {
				return signatureById;
			}
		}
		
		throw new IllegalArgumentException(String.format("A signature with Id '%s' has not been found in the file! Unable to counter sign.",
				parameters.getSignatureIdToCounterSign()));
	}
	
	private XAdESSignature getSignatureOrItsCounterSignatureById(XAdESSignature signature, String signatureId) {
		if (signatureId.equals(signature.getDAIdentifier()) || signatureId.equals(signature.getId())) {
			return signature;
		}
		
		for (AdvancedSignature counterSignature : signature.getCounterSignatures()) {
			XAdESSignature counterSignatureById = getSignatureOrItsCounterSignatureById((XAdESSignature) counterSignature, signatureId);
			if (counterSignatureById != null) {
				// check if not timestamped
				if (signature.getTimestampSource().isTimestamped(signatureId, TimestampedObjectType.SIGNATURE)) {
					throw new IllegalInputException(String.format("Unable to counter sign a signature with Id '%s'. "
							+ "The signature is timestamped by a master signature!", signatureId));
				}
				return counterSignatureById;
			}
		}
		
		return null;
	}
	
	private Element getSignatureValueElement(XAdESSignature xadesSignature) {
		Element signatureElement = xadesSignature.getSignatureElement();

		Element signatureValueElement = DomUtils.getElement(signatureElement, XMLDSigPaths.SIGNATURE_VALUE_PATH);
		if (signatureValueElement != null) {
			return signatureValueElement;
		}
		
		throw new IllegalInputException(String.format("Unable to counter sign a signature with Id '%s'. The SignatureValue element is not found!",
				xadesSignature.getDAIdentifier()));
	}

}
