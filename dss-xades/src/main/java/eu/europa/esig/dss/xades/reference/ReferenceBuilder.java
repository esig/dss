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
package eu.europa.esig.dss.xades.reference;

import eu.europa.esig.dss.DomUtils;
import eu.europa.esig.dss.definition.xmldsig.XMLDSigAttribute;
import eu.europa.esig.dss.definition.xmldsig.XMLDSigElement;
import eu.europa.esig.dss.definition.xmldsig.XMLDSigPaths;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.exception.IllegalInputException;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.xades.DSSXMLUtils;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 * Creates, validates references and processes defined transformations 
 *
 */
public class ReferenceBuilder {

	/**
	 * id-prefix for ds:Object element
	 */
	private static final String OBJECT_ID_PREFIX = "o-";

	/**
	 * List of documents to create references for
	 */
	private final List<DSSDocument> documents;

	/**
	 * The DigestAlgorithm to use
	 */
	private final DigestAlgorithm digestAlgorithm;

	/**
	 * Creates an identifier for a signature reference
	 */
	private final ReferenceIdProvider referenceIdProvider;
	
	/**
	 * The used XAdESSignatureParameters
	 */
	private XAdESSignatureParameters signatureParameters;

	/**
	 * The default constructor for a signature references creation
	 *
	 * @param documents a list of {@link DSSDocument}s to create references for
	 * @param xadesSignatureParameters {@link XAdESSignatureParameters}
	 * @param referenceIdProvider {@link ReferenceIdProvider}
	 */
	public ReferenceBuilder(final List<DSSDocument> documents, XAdESSignatureParameters xadesSignatureParameters,
							final ReferenceIdProvider referenceIdProvider) {
		Objects.requireNonNull(documents, "List of documents shall be provided!");
		Objects.requireNonNull(xadesSignatureParameters, "Signature parameters shall be provided!");
		this.documents = documents;
		this.signatureParameters = xadesSignatureParameters;
		this.digestAlgorithm = getReferenceDigestAlgorithmOrDefault(xadesSignatureParameters);
		this.referenceIdProvider = referenceIdProvider;
	}

	/**
	 * The default constructor for a detached references creation
	 *
	 * @param documents a list of detached {@link DSSDocument}s
	 * @param digestAlgorithm {@link DigestAlgorithm}
	 * @param referenceIdProvider {@link ReferenceIdProvider}
	 */
	public ReferenceBuilder(final List<DSSDocument> documents, final DigestAlgorithm digestAlgorithm,
							final ReferenceIdProvider referenceIdProvider) {
		Objects.requireNonNull(documents, "List of documents shall be provided!");
		Objects.requireNonNull(digestAlgorithm, "Digest Algorithm shall be provided!");
		this.documents = documents;
		this.digestAlgorithm = digestAlgorithm;
		this.referenceIdProvider = referenceIdProvider;
	}

	/**
	 * Builds a list of references based on the configuration
	 *
	 * @return a list of {@code DSSReference}s
	 */
	public List<DSSReference> build() {
		List<DSSReference> references = new ArrayList<>();
		for (DSSDocument dssDocument : documents) {
			references.add(createDSSReferenceForDocument(dssDocument));
		}
		return references;
	}
	
	private DSSReference createDSSReferenceForDocument(final DSSDocument document) {
		if (signatureParameters != null) {
			Objects.requireNonNull(signatureParameters.getSignaturePackaging(), "SignaturePackaging must be defined!");
			switch (signatureParameters.getSignaturePackaging()) {
				case ENVELOPED:
					return envelopedDSSReference(document);
				case ENVELOPING:
					return envelopingDSSReference(document);
				case DETACHED:
					return detachedDSSReference(document);
				case INTERNALLY_DETACHED:
					return internallyDetachedDSSReference(document);
				default:
					throw new DSSException(String.format("The given signature packaging %s is not supported!",
							signatureParameters.getSignaturePackaging()));
			}
		} else {
			// detached reference creation
			return detachedDSSReference(document);
		}
	}

	private DSSReference envelopedDSSReference(DSSDocument document) {
		assertEnvelopedSignaturePossible(document);

		DSSReference dssReference = new DSSReference();
		dssReference.setId(referenceIdProvider.getReferenceId());
		// XMLDSIG : 4.4.3.2
		// URI=""
		// Identifies the node-set (minus any comment nodes) of the XML resource
		// containing the signature
		dssReference.setUri("");
		dssReference.setContents(document);
		dssReference.setDigestMethodAlgorithm(digestAlgorithm);

		final List<DSSTransform> dssTransformList = new ArrayList<>();

		// For parallel signatures
		XPath2FilterEnvelopedSignatureTransform xPathTransform =
				new XPath2FilterEnvelopedSignatureTransform(signatureParameters.getXmldsigNamespace());
		dssTransformList.add(xPathTransform);

		// Canonicalization is the last operation, its better to operate the canonicalization on the smaller document
		CanonicalizationTransform canonicalizationTransform = 
				new CanonicalizationTransform(signatureParameters.getXmldsigNamespace(), DSSXMLUtils.DEFAULT_DSS_C14N_METHOD);
		dssTransformList.add(canonicalizationTransform);

		dssReference.setTransforms(dssTransformList);

		return dssReference;
	}

	private void assertEnvelopedSignaturePossible(DSSDocument document) {
		if (!DomUtils.isDOM(document)) {
			throw new IllegalInputException("Enveloped signature cannot be created. Reason : the provided document is not XML!");
		}
		Document dom = DomUtils.buildDOM(document);
		Element documentElement = dom.getDocumentElement();
		if (XMLDSigElement.SIGNATURE.isSameTagName(documentElement.getLocalName())) {
			throw new IllegalInputException("Unable to create an enveloped signature for another XML signature document!");
		}
	}

	private void assertEnvelopingSignatureWithEmbeddedXMLPossible(DSSDocument document) {
		if (!DomUtils.isDOM(document)) {
			throw new IllegalInputException("Enveloping signature with embedded XML cannot be created. " +
					"Reason : the provided document is not XML!");
		}
	}

	private DSSReference envelopingDSSReference(DSSDocument document) {
		// <ds:Reference Id="signed-data-ref" Type="http://www.w3.org/2000/09/xmldsig#Object"
		// URI="#signed-data-idfc5ff27ee49763d9ba88ba5bbc49f732">
		final String refId = referenceIdProvider.getReferenceId();
		final DSSReference reference = new DSSReference();
		reference.setId(refId);
		reference.setContents(document);
		reference.setDigestMethodAlgorithm(digestAlgorithm);

		if (signatureParameters.isManifestSignature()) {
			assertEnvelopingSignatureWithEmbeddedXMLPossible(document);

			Document manifestDoc = DomUtils.buildDOM(document);
			Element manifestElement = manifestDoc.getDocumentElement();
			assertXmlManifestSignaturePossible(manifestElement);

			reference.setType(XMLDSigPaths.MANIFEST_TYPE);
			reference.setUri(DomUtils.toElementReference(manifestElement.getAttribute(XMLDSigAttribute.ID.getAttributeName())));
			DSSTransform xmlTransform = new CanonicalizationTransform(signatureParameters.getXmldsigNamespace(), DSSXMLUtils.DEFAULT_DSS_C14N_METHOD);
			reference.setTransforms(Collections.singletonList(xmlTransform));

		} else if (signatureParameters.isEmbedXML()) {
			assertEnvelopingSignatureWithEmbeddedXMLPossible(document);

			reference.setType(XMLDSigPaths.OBJECT_TYPE);
			reference.setUri(DomUtils.toElementReference(OBJECT_ID_PREFIX + refId));

			DSSTransform xmlTransform = new CanonicalizationTransform(signatureParameters.getXmldsigNamespace(), DSSXMLUtils.DEFAULT_DSS_C14N_METHOD);
			reference.setTransforms(Collections.singletonList(xmlTransform));

		} else {
			reference.setType(XMLDSigPaths.OBJECT_TYPE);
			reference.setUri(DomUtils.toElementReference(OBJECT_ID_PREFIX + refId));

			DSSTransform base64Transform = new Base64Transform(signatureParameters.getXmldsigNamespace());
			reference.setTransforms(Collections.singletonList(base64Transform));
		}
		return reference;
	}

	private void assertXmlManifestSignaturePossible(Element manifestElement) {
		String idAttr = manifestElement.getAttribute(XMLDSigAttribute.ID.getAttributeName());
		if (Utils.isStringBlank(idAttr)) {
			throw new IllegalInputException(
					"Manifest signature is not possible for an XML file without Id attribute in the root element!");
		}
	}

	private DSSReference detachedDSSReference(DSSDocument document) {
		final DSSReference reference = new DSSReference();
		reference.setId(referenceIdProvider.getReferenceId());
		if (Utils.isStringNotEmpty(document.getName())) {
			reference.setUri(DSSUtils.encodeURI(document.getName()));
		}
		reference.setContents(document);
		reference.setDigestMethodAlgorithm(digestAlgorithm);
		return reference;
	}
	
	private DSSReference internallyDetachedDSSReference(DSSDocument document) {
		final DSSReference reference = new DSSReference();
		reference.setId(referenceIdProvider.getReferenceId());

		Document dom = DomUtils.buildDOM(document);
		String identifier = DSSXMLUtils.getIDIdentifier(dom.getDocumentElement());
		Objects.requireNonNull(identifier, "ID not defined on the root xml element");
		reference.setUri(DomUtils.toElementReference(identifier));

		reference.setContents(document);
		reference.setDigestMethodAlgorithm(digestAlgorithm);

		List<DSSTransform> dssTransformList = new ArrayList<>();
		CanonicalizationTransform canonicalization = new CanonicalizationTransform(
				signatureParameters.getXmldsigNamespace(), DSSXMLUtils.DEFAULT_DSS_C14N_METHOD);
		dssTransformList.add(canonicalization);
		reference.setTransforms(dssTransformList);
		return reference;
	}

	private DigestAlgorithm getReferenceDigestAlgorithmOrDefault(XAdESSignatureParameters params) {
		return params.getReferenceDigestAlgorithm() != null ? params.getReferenceDigestAlgorithm() : params.getDigestAlgorithm();
	}

}
