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

import java.util.List;

import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.XMLSignature;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.w3c.dom.Text;

import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.DSSXMLUtils;
import eu.europa.ec.markt.dss.DigestAlgorithm;
import eu.europa.ec.markt.dss.EncryptionAlgorithm;
import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.parameter.DSSReference;
import eu.europa.ec.markt.dss.parameter.DSSTransform;
import eu.europa.ec.markt.dss.parameter.SignatureParameters;
import eu.europa.ec.markt.dss.signature.DSSDocument;
import eu.europa.ec.markt.dss.signature.DSSSignatureUtils;
import eu.europa.ec.markt.dss.signature.InMemoryDocument;
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
	 *
	 * @param params  The set of parameters relating to the structure and process of the creation or extension of the electronic signature.
	 * @param origDoc The original document to sign.
	 */
	public EnvelopedSignatureBuilder(SignatureParameters params, DSSDocument origDoc) {

		super(params, origDoc);
		signedInfoCanonicalizationMethod = CanonicalizationMethod.EXCLUSIVE;
		reference2CanonicalizationMethod = CanonicalizationMethod.EXCLUSIVE;
	}

	/**
	 * This method creates the first reference (this is a reference to the file to be signed) witch is specific for each form of signature. Here, the value of the URI is set to
	 * http://www.w3.org/TR/1999/REC-xpath-19991116 (XPath recommendation) which means that an XPath-expression must be used to select a defined subset of the document tree.
	 */
	@Override
	protected void incorporateReference1() throws DSSException {

		final List<DSSReference> references = params.getReferences();
		final DSSReference reference = references.get(0);

		// <ds:Reference Id="xml_ref_id" URI="">
		final Element referenceDom = DSSXMLUtils.addElement(documentDom, signedInfoDom, XMLSignature.XMLNS, "ds:Reference");
		referenceDom.setAttribute("Id", reference.getId());
		referenceDom.setAttribute("URI", reference.getUri());

		final Element transformsDom = DSSXMLUtils.addElement(documentDom, referenceDom, XMLSignature.XMLNS, "ds:Transforms");

		final List<DSSTransform> transforms = reference.getTransforms();
		for (final DSSTransform transform : transforms) {

			final Element transformDom = DSSXMLUtils.addElement(documentDom, transformsDom, XMLSignature.XMLNS, "ds:Transform");
			transformDom.setAttribute("Algorithm", transform.getAlgorithm());
			final String elementName = transform.getElementName();
			if (elementName != null && !elementName.isEmpty()) {

				final String namespace = transform.getNamespace();
				final String textContent = transform.getTextContent();
				DSSXMLUtils.addTextElement(documentDom, transformDom, namespace, elementName, textContent);
			}
		}
		// <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
		final DigestAlgorithm digestAlgorithm = params.getDigestAlgorithm();
		incorporateDigestMethod(referenceDom, digestAlgorithm);

		// We remove existing signatures
		final Document domDoc = DSSXMLUtils.buildDOM(originalDocument);
		final NodeList signatureNodeList = domDoc.getElementsByTagNameNS(XMLSignature.XMLNS, XPathQueryHolder.XMLE_SIGNATURE);
		for (int ii = 0; ii < signatureNodeList.getLength(); ii++) {

			final Element signatureDOM = (Element) signatureNodeList.item(ii);
			signatureDOM.getParentNode().removeChild(signatureDOM);
		}
		byte[] canonicalizedBytes = DSSXMLUtils.canonicalizeSubtree(signedInfoCanonicalizationMethod, domDoc);
		if (LOG.isTraceEnabled()) {
			LOG.trace("Canonicalization method  -->" + signedInfoCanonicalizationMethod);
			LOG.trace("Canonicalized REF_1      --> " + new String(canonicalizedBytes));
		}
		incorporateDigestValue(referenceDom, digestAlgorithm, new InMemoryDocument(canonicalizedBytes));
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

		final Document originalDocumentDom = DSSXMLUtils.buildDOM(originalDocument);

		final Node copiedNode = originalDocumentDom.importNode(signatureDom, true);
		originalDocumentDom.getDocumentElement().appendChild(copiedNode);

		byte[] documentBytes = DSSXMLUtils.transformDomToByteArray(originalDocumentDom);
		return new InMemoryDocument(documentBytes);
	}

	/**
	 * This method returns data format reference specific for enveloped signature.
	 */
	@Override
	protected String getDataObjectFormatObjectReference() {

		return "#xml_ref_id";
	}

	/**
	 * This method returns data format mime type specific for enveloped signature.
	 */
	@Override
	protected String getDataObjectFormatMimeType() {

		return "text/xml";
	}
}