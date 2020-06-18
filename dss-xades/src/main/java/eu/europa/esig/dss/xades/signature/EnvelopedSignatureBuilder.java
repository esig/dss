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

import java.util.ArrayList;
import java.util.List;

import javax.xml.crypto.dsig.CanonicalizationMethod;

import org.w3c.dom.Document;
import org.w3c.dom.Node;

import eu.europa.esig.dss.DomUtils;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.xades.DSSXMLUtils;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.reference.CanonicalizationTransform;
import eu.europa.esig.dss.xades.reference.DSSReference;
import eu.europa.esig.dss.xades.reference.DSSTransform;
import eu.europa.esig.dss.xades.reference.XPathEnvelopedSignatureTransform;

/**
 * This class handles the specifics of the enveloped XML signature
 *
 */
class EnvelopedSignatureBuilder extends XAdESSignatureBuilder {

	/**
	 * The default constructor for EnvelopedSignatureBuilder. The enveloped signature uses by default the exclusive
	 * method of canonicalization.
	 * 
	 * @param params
	 *            The set of parameters relating to the structure and process of the creation or extension of the
	 *            electronic signature.
	 * @param origDoc
	 *            The original document to sign.
	 * @param certificateVerifier
	 */
	public EnvelopedSignatureBuilder(final XAdESSignatureParameters params, final DSSDocument origDoc, final CertificateVerifier certificateVerifier) {
		super(params, origDoc, certificateVerifier);
		setCanonicalizationMethods(params, DEFAULT_CANONICALIZATION_METHOD);
	}

	/**
	 * In case of enveloped signature, the document should be the original file. Important for inclusive
	 * canonicalization and namespaces
	 */
	@Override
	protected Document buildRootDocumentDom() {
		return DomUtils.buildDOM(detachedDocument);
	}

	@Override
	protected Node getParentNodeOfSignature() {
		final String xPathLocationString = params.getXPathLocationString();
		if (Utils.isStringNotEmpty(xPathLocationString)) {
			return DomUtils.getElement(documentDom, xPathLocationString);
		}
		return documentDom.getDocumentElement();
	}
	
	@Override
	protected void incorporateSignatureDom(Node parentNodeOfSignature) {
	    if (params.getXPathElementPlacement() == null || Utils.isStringEmpty(params.getXPathLocationString())) {
		parentNodeOfSignature.appendChild(signatureDom);
		return;
	    }

	    switch (params.getXPathElementPlacement()) {
		    case XPathAfter:
			    // root element referenced by XPath
			    if (parentNodeOfSignature.isEqualNode(documentDom.getDocumentElement())) { 
				    // append signature at end of document
				    parentNodeOfSignature.appendChild(signatureDom);
				    
			    } else {
				    // insert signature before next sibling or as last child
				    // if no sibling exists
				    Node parent = parentNodeOfSignature.getParentNode();
				    parent.insertBefore(signatureDom, parentNodeOfSignature.getNextSibling());
			    }

			    break;
		    case XPathFirstChildOf:
			    parentNodeOfSignature.insertBefore(signatureDom, parentNodeOfSignature.getFirstChild());
			    break;
		    default:
			    parentNodeOfSignature.appendChild(signatureDom);
			    break;
	    }
	}

	@Override
	protected DSSReference createReference(DSSDocument document, int referenceIndex) {

		DSSReference dssReference = new DSSReference();
		dssReference.setId(REFERENCE_ID_SUFFIX + deterministicId + "-" + referenceIndex);
		// XMLDSIG : 4.4.3.2
		// URI=""
		// Identifies the node-set (minus any comment nodes) of the XML resource
		// containing the signature
		dssReference.setUri("");
		dssReference.setContents(document);
		DigestAlgorithm digestAlgorithm = getReferenceDigestAlgorithmOrDefault(params);
		dssReference.setDigestMethodAlgorithm(digestAlgorithm);

		final List<DSSTransform> dssTransformList = new ArrayList<>();

		// For parallel signatures
		XPathEnvelopedSignatureTransform xPathTransform = new XPathEnvelopedSignatureTransform(getXmldsigNamespace());
		dssTransformList.add(xPathTransform);

		// Canonicalization is the last operation, its better to operate the canonicalization on the smaller document
		CanonicalizationTransform canonicalizationTransform = new CanonicalizationTransform(getXmldsigNamespace(), CanonicalizationMethod.EXCLUSIVE);
		dssTransformList.add(canonicalizationTransform);

		dssReference.setTransforms(dssTransformList);

		return dssReference;
	}

	/**
	 * Preconditions:
	 * - The reference data is XML
	 * - The last transformation is canonicalization.
	 *
	 * @param reference
	 *            {@code DSSReference} to be transformed
	 * @return {@code DSSDocument} containing transformed reference's data
	 */
	@Override
	protected DSSDocument transformReference(final DSSReference reference) {

		DSSDocument dssDocument = reference.getContents();

		// In the case of ENVELOPED signature the document to sign is an XML. However one of the references can point to
		// another document this test case is not taken into account!

		Node nodeToTransform = null;
		final String uri = reference.getUri();
		// Check if the reference is related to the whole document
		if (Utils.isStringNotBlank(uri) && uri.startsWith("#") && !isXPointer(uri)) {
			final Document document = DomUtils.buildDOM(dssDocument);
			DSSXMLUtils.recursiveIdBrowse(document.getDocumentElement());
			final String targetId = DomUtils.getId(uri);
			nodeToTransform = document.getElementById(targetId);
			
		}
		if (Utils.isCollectionEmpty(reference.getTransforms())) {
			if (nodeToTransform == null) {
				return dssDocument;
			} else {
				byte[] nodeBytes = DSSXMLUtils.getNodeBytes(nodeToTransform);
				return new InMemoryDocument(nodeBytes);
			}
		}
		if (nodeToTransform == null) {
			nodeToTransform = DomUtils.buildDOM(dssDocument);
		}
		
		byte[] transformedReferenceBytes = applyTransformations(reference, nodeToTransform);
		return new InMemoryDocument(transformedReferenceBytes);
	}

	private static boolean isXPointer(final String uri) {
		final boolean xPointer = uri.startsWith("#xpointer(") || uri.startsWith("#xmlns(");
		return xPointer;
	}

}
