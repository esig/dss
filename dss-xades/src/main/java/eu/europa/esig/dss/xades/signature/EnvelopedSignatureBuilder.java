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
import javax.xml.crypto.dsig.XMLSignature;

import org.apache.xml.security.transforms.Transforms;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.DomUtils;
import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.xades.DSSReference;
import eu.europa.esig.dss.xades.DSSTransform;
import eu.europa.esig.dss.xades.DSSXMLUtils;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.XPathQueryHolder;

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
		setCanonicalizationMethods(params, CanonicalizationMethod.EXCLUSIVE);
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
	protected DSSReference createReference(DSSDocument document, int referenceIndex) {

		DSSReference dssReference = new DSSReference();
		dssReference.setId("r-id-" + referenceIndex);
		// XMLDSIG : 4.4.3.2
		// URI=""
		// Identifies the node-set (minus any comment nodes) of the XML resource
		// containing the signature
		dssReference.setUri("");
		dssReference.setContents(document);
		DigestAlgorithm digestAlgorithm = params.getReferenceDigestAlgorithm() != null ? params.getReferenceDigestAlgorithm() : params.getDigestAlgorithm();
		dssReference.setDigestMethodAlgorithm(digestAlgorithm);

		final List<DSSTransform> dssTransformList = new ArrayList<DSSTransform>();

		// For parallel signatures
		DSSTransform dssTransform = new DSSTransform();
		dssTransform.setAlgorithm(Transforms.TRANSFORM_XPATH);
		dssTransform.setElementName(DS_XPATH);
		dssTransform.setNamespace(XMLSignature.XMLNS);
		dssTransform.setTextContent(NOT_ANCESTOR_OR_SELF_DS_SIGNATURE);
		dssTransformList.add(dssTransform);

		// Canonicalization is the last operation, its better to operate the canonicalization on the smaller document
		dssTransform = new DSSTransform();
		dssTransform.setAlgorithm(CanonicalizationMethod.EXCLUSIVE);
		dssTransformList.add(dssTransform);

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
		final List<DSSTransform> transforms = reference.getTransforms();
		if (Utils.isCollectionEmpty(transforms)) {
			return dssDocument;
		}

		// In the case of ENVELOPED signature the document to sign is an XML. However one of the references can point to
		// another document this test case is not taken into account!

		Node nodeToTransform = null;
		final String uri = reference.getUri();
		// Check if the reference is related to the whole document
		if (Utils.isStringNotBlank(uri) && uri.startsWith("#") && !isXPointer(uri)) {

			final Document document = DomUtils.buildDOM(dssDocument);
			DSSXMLUtils.recursiveIdBrowse(document.getDocumentElement());
			final String uri_id = uri.substring(1);
			nodeToTransform = document.getElementById(uri_id);
		}
		byte[] transformedReferenceBytes = applyTransformations(dssDocument, transforms, nodeToTransform);
		return new InMemoryDocument(transformedReferenceBytes);
	}

	private static boolean isXPointer(final String uri) {
		final boolean xPointer = uri.startsWith("#xpointer(") || uri.startsWith("#xmlns(");
		return xPointer;
	}

	/**
	 * Bob --> This method is not used anymore, but it can replace {@code NOT_ANCESTOR_OR_SELF_DS_SIGNATURE}
	 * transformation. Performance test should be performed!
	 * In case of the enveloped signature the existing signatures are removed.
	 *
	 * @param domDoc
	 *            {@code Document} containing the signatures to analyse
	 */
	protected void removeExistingSignatures(final Document domDoc) {

		final NodeList signatureNodeList = domDoc.getElementsByTagNameNS(XMLSignature.XMLNS, XPathQueryHolder.XMLE_SIGNATURE);
		for (int ii = signatureNodeList.getLength() - 1; ii >= 0; ii--) {
			final Element signatureDOM = (Element) signatureNodeList.item(ii);
			signatureDOM.getParentNode().removeChild(signatureDOM);
		}
	}

}
