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
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.DigestDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.xades.DSSXMLUtils;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import org.apache.xml.security.transforms.Transforms;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

/**
 * Creates, validates references and processes defined transformations 
 *
 */
public class ReferenceBuilder {

	private static final Logger LOG = LoggerFactory.getLogger(ReferenceBuilder.class);
	
	/**
	 * The used XAdESSignatureParameters
	 */
	private final XAdESSignatureParameters signatureParameters;

	/** id-suffix for ds:Object element */
	private static final String OBJECT_ID_SUFFIX = "o-";

	/** id-suffix for ds:Reference element */
	private static final String REFERENCE_ID_SUFFIX = "r-";
	
	/**
	 * The default constructor
	 * 
	 * @param xadesSignatureParameters {@link XAdESSignatureParameters}
	 */
	public ReferenceBuilder(final XAdESSignatureParameters xadesSignatureParameters) {
		Objects.requireNonNull(xadesSignatureParameters, "Signature parameters cannot be null!");
		this.signatureParameters = xadesSignatureParameters;
	}
	
	/**
	 * Builds a list of references based on the configuration
	 * 
	 * @param documents a list of {@link DSSDocument} to create references for
	 * @return a list of {@code DSSReference}s
	 */
	public List<DSSReference> build(List<DSSDocument> documents) {
		List<DSSReference> references = new ArrayList<>();
		int referenceIndex = 1;
		for (DSSDocument dssDocument : documents) {
			references.add(createDSSReferenceForDocument(dssDocument, referenceIndex));
			referenceIndex++;
		}
		return references;
	}
	
	private DSSReference createDSSReferenceForDocument(final DSSDocument document, final int index) {
		Objects.requireNonNull(signatureParameters.getSignaturePackaging(), "SignaturePackaging must be defined!");
		switch (signatureParameters.getSignaturePackaging()) {
			case ENVELOPED:
				return envelopedDSSReference(document, index);
			case ENVELOPING:
				return envelopingDSSReference(document, index);
			case DETACHED:
				return detachedDSSReference(document, index);
			case INTERNALLY_DETACHED:
				return internallyDetachedDSSReference(document, index);
			default:
				throw new DSSException(String.format("The given signature packaging %s is not supported!", 
						signatureParameters.getSignaturePackaging()));
		}
	}

	private DSSReference envelopedDSSReference(DSSDocument document, int index) {
		DSSReference dssReference = new DSSReference();
		dssReference.setId(REFERENCE_ID_SUFFIX + getReferenceId(index));
		// XMLDSIG : 4.4.3.2
		// URI=""
		// Identifies the node-set (minus any comment nodes) of the XML resource
		// containing the signature
		dssReference.setUri("");
		dssReference.setContents(document);
		DigestAlgorithm digestAlgorithm = getReferenceDigestAlgorithmOrDefault(signatureParameters);
		dssReference.setDigestMethodAlgorithm(digestAlgorithm);

		final List<DSSTransform> dssTransformList = new ArrayList<>();

		// For parallel signatures
		XPath2FilterEnvelopedSignatureTransform xPathTransform = new XPath2FilterEnvelopedSignatureTransform(signatureParameters.getXmldsigNamespace());
		dssTransformList.add(xPathTransform);

		// Canonicalization is the last operation, its better to operate the canonicalization on the smaller document
		CanonicalizationTransform canonicalizationTransform = 
				new CanonicalizationTransform(signatureParameters.getXmldsigNamespace(), DSSXMLUtils.DEFAULT_DSS_C14N_METHOD);
		dssTransformList.add(canonicalizationTransform);

		dssReference.setTransforms(dssTransformList);

		return dssReference;
	}

	private DSSReference envelopingDSSReference(DSSDocument document, int index) {
		// <ds:Reference Id="signed-data-ref" Type="http://www.w3.org/2000/09/xmldsig#Object"
		// URI="#signed-data-idfc5ff27ee49763d9ba88ba5bbc49f732">
		final String refId = getReferenceId(index);
		final DSSReference reference = new DSSReference();
		reference.setId(REFERENCE_ID_SUFFIX + refId);
		reference.setContents(document);
		DigestAlgorithm digestAlgorithm = getReferenceDigestAlgorithmOrDefault(signatureParameters);
		reference.setDigestMethodAlgorithm(digestAlgorithm);

		if (signatureParameters.isManifestSignature()) {
			reference.setType(XMLDSigPaths.MANIFEST_TYPE);
			Document manifestDoc = DomUtils.buildDOM(document);
			Element manifestElement = manifestDoc.getDocumentElement();
			reference.setUri("#" + manifestElement.getAttribute(XMLDSigAttribute.ID.getAttributeName()));
			DSSTransform xmlTransform = new CanonicalizationTransform(signatureParameters.getXmldsigNamespace(), DSSXMLUtils.DEFAULT_DSS_C14N_METHOD);
			reference.setTransforms(Arrays.asList(xmlTransform));
		} else if (signatureParameters.isEmbedXML()) {
			reference.setType(XMLDSigPaths.OBJECT_TYPE);
			reference.setUri("#" + OBJECT_ID_SUFFIX + refId);

			DSSTransform xmlTransform = new CanonicalizationTransform(signatureParameters.getXmldsigNamespace(), DSSXMLUtils.DEFAULT_DSS_C14N_METHOD);
			reference.setTransforms(Arrays.asList(xmlTransform));
		} else {
			reference.setType(XMLDSigPaths.OBJECT_TYPE);
			reference.setUri("#" + OBJECT_ID_SUFFIX + refId);

			DSSTransform base64Transform = new Base64Transform(signatureParameters.getXmldsigNamespace());
			reference.setTransforms(Arrays.asList(base64Transform));
		}
		return reference;
	}

	private DSSReference detachedDSSReference(DSSDocument document, int index) {
		final DSSReference reference = new DSSReference();
		reference.setId(REFERENCE_ID_SUFFIX + getReferenceId(index));
		if (Utils.isStringNotEmpty(document.getName())) {
			reference.setUri(DSSUtils.encodeURI(document.getName()));
		}
		reference.setContents(document);
		DigestAlgorithm digestAlgorithm = getReferenceDigestAlgorithmOrDefault(signatureParameters);
		reference.setDigestMethodAlgorithm(digestAlgorithm);
		return reference;
	}
	
	private DSSReference internallyDetachedDSSReference(DSSDocument document, int index) {
		final DSSReference reference = new DSSReference();
		reference.setId(REFERENCE_ID_SUFFIX + getReferenceId(index));

		Document dom = DomUtils.buildDOM(document);
		String identifier = DSSXMLUtils.getIDIdentifier(dom.getDocumentElement());
		Objects.requireNonNull(identifier, "ID not defined on the root xml element");
		reference.setUri("#" + identifier);

		reference.setContents(document);
		DigestAlgorithm digestAlgorithm = getReferenceDigestAlgorithmOrDefault(signatureParameters);
		reference.setDigestMethodAlgorithm(digestAlgorithm);

		List<DSSTransform> dssTransformList = new ArrayList<>();
		CanonicalizationTransform canonicalization = new CanonicalizationTransform(
				signatureParameters.getXmldsigNamespace(), DSSXMLUtils.DEFAULT_DSS_C14N_METHOD);
		dssTransformList.add(canonicalization);
		reference.setTransforms(dssTransformList);
		return reference;
	}
	
	private String getReferenceId(int index) {
		return signatureParameters.getDeterministicId() + "-" + index;
	}
	
	private DigestAlgorithm getReferenceDigestAlgorithmOrDefault(XAdESSignatureParameters params) {
		return params.getReferenceDigestAlgorithm() != null ? params.getReferenceDigestAlgorithm() : params.getDigestAlgorithm();
	}
	
	/**
	 * Returns an output content after processing the given {@code DSSReference}
	 * 
	 * @param reference {@link DSSReference} to process
	 * @return {@link DSSDocument} reference output content
	 */
	public DSSDocument getReferenceOutput(DSSReference reference) {
		if (reference.getContents() instanceof DigestDocument) {
			return reference.getContents();
		}

		Node nodeToTransform = dereferenceNode(reference);
		if (nodeToTransform == null) {
			return reference.getContents();
		}
		List<DSSTransform> transforms = reference.getTransforms();
		if (isUniqueBase64Tranform(transforms)) {
			return reference.getContents();
		}

		byte[] referenceOutputResult = DSSXMLUtils.applyTransforms(nodeToTransform, reference.getTransforms());

		if (ReferenceOutputType.NODE_SET.equals(DSSXMLUtils.getReferenceOutputType(reference)) && DomUtils.isDOM(referenceOutputResult)) {
			referenceOutputResult = DSSXMLUtils.canonicalize(DSSXMLUtils.DEFAULT_XMLDSIG_C14N_METHOD, referenceOutputResult);
		}
		if (LOG.isDebugEnabled()) {
			LOG.debug(new String(referenceOutputResult));
		}
		return new InMemoryDocument(referenceOutputResult);
	}
	
	private Node dereferenceNode(DSSReference reference) {
		Node dereferencedNode = getNodeToTransform(reference);
		if (dereferencedNode != null && DSSXMLUtils.isSameDocumentReference(reference.getUri())) {
			dereferencedNode = DomUtils.excludeComments(dereferencedNode);
		}
		return dereferencedNode;
	}

	private Node getNodeToTransform(DSSReference reference) {
		DSSDocument contents = reference.getContents();		
		byte[] docBinaries = DSSUtils.toByteArray(contents);
		if (!DomUtils.isDOM(docBinaries)) {
			// cannot be transformed
			return null;
		}
		
		String uri = reference.getUri();
		
		if (signatureParameters.isEmbedXML()) {
			Document doc = DomUtils.buildDOM(contents);
			Element root = doc.getDocumentElement();

			Document doc2 = DomUtils.buildDOM();
			final Element dom = DomUtils.createElementNS(doc2, signatureParameters.getXmldsigNamespace(), XMLDSigElement.OBJECT);
			final Element dom2 = DomUtils.createElementNS(doc2, signatureParameters.getXmldsigNamespace(), XMLDSigElement.OBJECT);
			doc2.appendChild(dom2);
			dom2.appendChild(dom);
			dom.setAttribute(XMLDSigAttribute.ID.getAttributeName(), DomUtils.getId(uri));

			Node adopted = doc2.adoptNode(root);
			dom.appendChild(adopted);
			return dom;
			
		} else if (!Utils.isStringBlank(uri) && uri.startsWith("#") && !isXPointer(uri)) {
			final Document document = DomUtils.buildDOM(contents);
			DSSXMLUtils.recursiveIdBrowse(document.getDocumentElement());
			final String targetId = DomUtils.getId(uri);
			Element elementById = document.getElementById(targetId);
			if (elementById != null) {
				return elementById;
			}
			
		}
		
		if (Utils.isCollectionNotEmpty(reference.getTransforms())) {
			return DomUtils.buildDOM(contents);
		}
		
		return null;
		
	}
	
	private static boolean isXPointer(final String uri) {
		final boolean xPointer = uri.startsWith("#xpointer(") || uri.startsWith("#xmlns(");
		return xPointer;
	}
	
	private boolean isUniqueBase64Tranform(List<DSSTransform> transforms) {
		return transforms != null && transforms.size() == 1 && transforms.get(0) instanceof Base64Transform;
	}
	
	/**
	 * Verifies a compatibility of defined signature parameters and reference transformations
	 */
	public void checkReferencesValidity() {
		String referenceWrongMessage = "Reference setting is not correct! ";
		for (DSSReference reference : signatureParameters.getReferences()) {
			List<DSSTransform> transforms = reference.getTransforms();
			if (Utils.isCollectionNotEmpty(transforms)) {
				for (DSSTransform transform : transforms) {
					switch (transform.getAlgorithm()) {
					case Transforms.TRANSFORM_BASE64_DECODE:
						if (signatureParameters.isEmbedXML()) {
							throw new DSSException(referenceWrongMessage + "The embedXML(true) parameter is not compatible with base64 transform.");
						} else if (signatureParameters.isManifestSignature()) {
							throw new DSSException(referenceWrongMessage + "Manifest signature is not compatible with base64 transform.");
						} else if (!SignaturePackaging.ENVELOPING.equals(signatureParameters.getSignaturePackaging())) {
							throw new DSSException(referenceWrongMessage + 
									String.format("Base64 transform is not compatible with %s signature format.", signatureParameters.getSignaturePackaging()));
						} else if (transforms.size() > 1) {
							throw new DSSException(referenceWrongMessage + "Base64 transform cannot be used with other transformations.");
						}
						break;
					default:
						// do nothing
						break;
					}
				}
				
			} else {
				String uri = reference.getUri();
				if (Utils.isStringBlank(uri) || DomUtils.isElementReference(uri)) {
					LOG.warn("A reference with id='{}' and uri='{}' points to an XML Node, while no transforms are defined! "
							+ "The configuration can lead to an unexpected result!", reference.getId(), uri);
				}
				if (SignaturePackaging.ENVELOPED.equals(signatureParameters.getSignaturePackaging()) && Utils.isStringBlank(uri)) {
					throw new DSSException(referenceWrongMessage + "Enveloped signature must have an enveloped transformation!");
				}
				
			}
		}
	}

}
