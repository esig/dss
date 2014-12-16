/*
 * DSS - Digital Signature Services
 *
 * Copyright (C) 2013 European Commission, Directorate-General Internal Market and Services (DG MARKT), B-1049 Bruxelles/Brussel
 *
 * Developed by: 2013 ARHS Developments S.A. (rue Nicolas Bové 2B, L-1253 Luxembourg) http://www.arhs-developments.com
 *
 * This file is part of the "DSS - Digital Signature Services" project.
 *
 * "DSS - Digital Signature Services" is free software: you can redistribute it and/or modify it under the terms of
 * the GNU Lesser General Public License as published by the Free Software Foundation, either version 2.1 of the
 * License, or (at your option) any later version.
 *
 * DSS is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License along with
 * "DSS - Digital Signature Services".  If not, see <http://www.gnu.org/licenses/>.
 */

package eu.europa.ec.markt.dss.signature.xades;

import java.util.ArrayList;
import java.util.List;

import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.XMLSignature;

import org.apache.xml.security.transforms.Transforms;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.w3c.dom.Text;

import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.DSSXMLUtils;
import eu.europa.ec.markt.dss.EncryptionAlgorithm;
import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.parameter.DSSReference;
import eu.europa.ec.markt.dss.parameter.DSSTransform;
import eu.europa.ec.markt.dss.parameter.SignatureParameters;
import eu.europa.ec.markt.dss.signature.DSSDocument;
import eu.europa.ec.markt.dss.signature.DSSSignatureUtils;
import eu.europa.ec.markt.dss.signature.InMemoryDocument;
import eu.europa.ec.markt.dss.signature.MimeType;
import eu.europa.ec.markt.dss.validation102853.CertificateVerifier;
import eu.europa.ec.markt.dss.validation102853.xades.XPathQueryHolder;

/**
 * This class handles the specifics of the enveloped XML signature
 * <p/>
 * <p> DISCLAIMER: Project owner DG-MARKT.
 *
 * @author <a href="mailto:dgmarkt.Project-DSS@arhs-developments.com">ARHS Developments</a>
 * @version $Revision: 672 $ - $Date: 2011-05-12 11:59:21 +0200 (Thu, 12 May 2011) $
 */
class EnvelopedSignatureBuilder extends SignatureBuilder {

	/**
	 * The default constructor for EnvelopedSignatureBuilder. The enveloped signature uses by default the exclusive method of canonicalization.
	 *  @param params  The set of parameters relating to the structure and process of the creation or extension of the electronic signature.
	 * @param origDoc The original document to sign.
	 * @param certificateVerifier
	 */
	public EnvelopedSignatureBuilder(final SignatureParameters params, final DSSDocument origDoc, final CertificateVerifier certificateVerifier) {

		super(params, origDoc, certificateVerifier);
		// Inclusive method does not work with the enveloped signature. This limitation comes from the mechanism used by the framework to build the signature.
		// Ditto: "http://www.w3.org/2006/12/xml-c14n11"
		setSignedInfoCanonicalizationMethod(params, CanonicalizationMethod.EXCLUSIVE);
		signedPropertiesCanonicalizationMethod = CanonicalizationMethod.EXCLUSIVE;
	}

	/**
	 * {@inheritDoc}
	 * Per default the value of the URI is set to http://www.w3.org/TR/1999/REC-xpath-19991116 (XPath recommendation) which means that an XPath-expression must be used to select a
	 * defined subset of the document tree.
	 */
	@Override
	protected void incorporateReferences() throws DSSException {

		final List<DSSReference> references = params.getReferences();
		for (final DSSReference reference : references) {

			incorporateReference(reference);
		}
	}

	@Override
	protected List<DSSReference> createDefaultReferences() {

		final List<DSSReference> dssReferences = new ArrayList<DSSReference>();

		DSSReference dssReference = new DSSReference();
		dssReference.setId("r-id-1");
		dssReference.setUri("");
		dssReference.setContents(detachedDocument);
		dssReference.setDigestMethodAlgorithm(params.getDigestAlgorithm());

		final List<DSSTransform> dssTransformList = new ArrayList<DSSTransform>();

		// For parallel signatures
		DSSTransform dssTransform = new DSSTransform();
		dssTransform.setAlgorithm(Transforms.TRANSFORM_XPATH);
		dssTransform.setElementName(DS_XPATH);
		dssTransform.setNamespace(XMLSignature.XMLNS);
		dssTransform.setTextContent(NOT_ANCESTOR_OR_SELF_DS_SIGNATURE);
		dssTransform.setPerform(true);
		dssTransformList.add(dssTransform);

		// Canonicalization is the last operation, its better to operate the canonicalization on the smaller document
		dssTransform = new DSSTransform();
		dssTransform.setAlgorithm(CanonicalizationMethod.EXCLUSIVE);
		dssTransform.setPerform(true);
		dssTransformList.add(dssTransform);

		dssReference.setTransforms(dssTransformList);
		dssReferences.add(dssReference);

		return dssReferences;
	}

	@Override
	protected MimeType getReferenceMimeType(final DSSReference reference) {

		return MimeType.XML;
	}

	/**
	 * Preconditions:
	 * - The reference data is XML
	 * - The last transformation is canonicalization.
	 *
	 * @param reference {@code DSSReference} to be transformed
	 * @return {@code DSSDocument} containing transformed reference's data
	 */
	@Override
	protected DSSDocument transformReference(final DSSReference reference) {

		DSSDocument dssDocument = reference.getContents();
		final List<DSSTransform> transforms = reference.getTransforms();
		if (shouldPerformTransformations(transforms)) {
			return dssDocument;
		}
		// In the case of ENVELOPED signature the document to sign is an XML. However one of the references can point to another document this test case is not taken into account!

		Node nodeToTransform = null;
		final String uri = reference.getUri();
		// Check if the reference is related to the whole document
		if (DSSUtils.isNotBlank(uri) && uri.startsWith("#") && !isXPointer(uri)) {

			final Document document = DSSXMLUtils.buildDOM(dssDocument);
			DSSXMLUtils.recursiveIdBrowse(document.getDocumentElement());
			final String uri_id = uri.substring(1);
			nodeToTransform = document.getElementById(uri_id);
		}
		byte[] transformedReferenceBytes = null;
		if (DSSUtils.isEmpty(transforms)) {
			transformedReferenceBytes = DSSXMLUtils.serializeNode(nodeToTransform);
		} else {
			transformedReferenceBytes = applyTransformations(dssDocument, transforms, nodeToTransform, transformedReferenceBytes);
		}
		return new InMemoryDocument(transformedReferenceBytes);
	}

	private byte[] applyTransformations(DSSDocument dssDocument, final List<DSSTransform> transforms, Node nodeToTransform, byte[] transformedReferenceBytes) {

		for (final DSSTransform transform : transforms) {

			final String transformAlgorithm = transform.getAlgorithm();
			if (Transforms.TRANSFORM_XPATH.equals(transformAlgorithm)) {

				final DSSTransformXPath transformXPath = new DSSTransformXPath(transform);
				// At the moment it is impossible to go through a medium other than byte array (Set<Node>, octet stream, Node). Further investigation is needed.
				final byte[] transformedBytes = nodeToTransform == null ? transformXPath.transform(dssDocument) : transformXPath.transform(nodeToTransform);
				dssDocument = new InMemoryDocument(transformedBytes);
				nodeToTransform = DSSXMLUtils.buildDOM(dssDocument);
			} else if (DSSXMLUtils.canCanonicalize(transformAlgorithm)) {

				if (nodeToTransform == null) {
					nodeToTransform = DSSXMLUtils.buildDOM(dssDocument);
				}
				transformedReferenceBytes = DSSXMLUtils.canonicalizeSubtree(transformAlgorithm, nodeToTransform);
				// The supposition is made that the last transformation is the canonicalization
				break;
			} else if (CanonicalizationMethod.ENVELOPED.equals(transformAlgorithm)) {

				// do nothing the new signature is not existing yet!
				// removeExistingSignatures(document);
			} else {
				throw new DSSException("The transformation is not implemented yet, please transform the reference before signing!");
			}
		}
		return transformedReferenceBytes;
	}

	private boolean shouldPerformTransformations(final List<DSSTransform> transforms) {

		if (transforms != null) {
			for (final DSSTransform transform : transforms) {
				if (!transform.isPerform()) {
					return true;
				}
			}
		}
		return false;
	}

	private static boolean isXPointer(final String uri) {

		final boolean xPointer = uri.startsWith("#xpointer(") || uri.startsWith("#xmlns(");
		return xPointer;
	}

	/**
	 * Bob --> This method is not used anymore, but it can replace {@code NOT_ANCESTOR_OR_SELF_DS_SIGNATURE} transformation. Performance test should be performed!
	 * In case of the enveloped signature the existing signatures are removed.
	 *
	 * @param domDoc {@code Document} containing the signatures to analyse
	 */
	protected void removeExistingSignatures(final Document domDoc) {

		final NodeList signatureNodeList = domDoc.getElementsByTagNameNS(XMLSignature.XMLNS, XPathQueryHolder.XMLE_SIGNATURE);
		for (int ii = signatureNodeList.getLength() - 1; ii >= 0; ii--) {

			final Element signatureDOM = (Element) signatureNodeList.item(ii);
			signatureDOM.getParentNode().removeChild(signatureDOM);
		}
	}

	/**
	 * Adds signature value to the signature and returns XML signature (InMemoryDocument)
	 *
	 * @param signatureValue
	 * @return
	 * @throws DSSException
	 */
	@Override
	public DSSDocument signDocument(final byte[] signatureValue) throws DSSException {

		if (!built) {

			build();
		}
		final EncryptionAlgorithm encryptionAlgorithm = params.getEncryptionAlgorithm();
		final byte[] signatureValueBytes = DSSSignatureUtils.convertToXmlDSig(encryptionAlgorithm, signatureValue);
		final String signatureValueBase64Encoded = DSSUtils.base64Encode(signatureValueBytes);
		final Text signatureValueNode = documentDom.createTextNode(signatureValueBase64Encoded);
		signatureValueDom.appendChild(signatureValueNode);

		final Document originalDocumentDom = DSSXMLUtils.buildDOM(detachedDocument);
		final Node copiedNode = originalDocumentDom.importNode(signatureDom, true);

		if (params.getXPathLocationString() != null) {
			DSSXMLUtils.getElement(originalDocumentDom, params.getXPathLocationString()).appendChild(copiedNode);
		} else {
			originalDocumentDom.getDocumentElement().appendChild(copiedNode);
		}

		byte[] documentBytes = DSSXMLUtils.transformDomToByteArray(originalDocumentDom);
		final InMemoryDocument inMemoryDocument = new InMemoryDocument(documentBytes);
		inMemoryDocument.setMimeType(MimeType.XML);
		return inMemoryDocument;
	}
}