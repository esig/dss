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

import java.util.Arrays;
import java.util.List;

import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.XMLSignature;

import org.apache.xml.security.c14n.Canonicalizer;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.Text;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.DomUtils;
import eu.europa.esig.dss.EncryptionAlgorithm;
import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.MimeType;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.xades.DSSReference;
import eu.europa.esig.dss.xades.DSSTransform;
import eu.europa.esig.dss.xades.DSSXMLUtils;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;

/**
 * This class handles the specifics of the enveloping XML signature
 *
 */
class EnvelopingSignatureBuilder extends XAdESSignatureBuilder {

	/**
	 * The default constructor for EnvelopingSignatureBuilder. The enveloped signature uses by default the inclusive
	 * method of canonicalization.
	 * 
	 * @param params
	 *            The set of parameters relating to the structure and process of the creation or extension of the
	 *            electronic signature.
	 * @param origDoc
	 *            The original document to sign.
	 * @param certificateVerifier
	 */
	public EnvelopingSignatureBuilder(final XAdESSignatureParameters params, final DSSDocument origDoc, final CertificateVerifier certificateVerifier) {
		super(params, origDoc, certificateVerifier);
		setCanonicalizationMethods(params, CanonicalizationMethod.INCLUSIVE);
	}

	@Override
	protected DSSReference createReference(DSSDocument document, int referenceIndex) {
		// <ds:Reference Id="signed-data-ref" Type="http://www.w3.org/2000/09/xmldsig#Object"
		// URI="#signed-data-idfc5ff27ee49763d9ba88ba5bbc49f732">
		final DSSReference reference = new DSSReference();
		reference.setId("r-id-" + referenceIndex);
		reference.setType(HTTP_WWW_W3_ORG_2000_09_XMLDSIG_OBJECT);
		reference.setUri("#o-id-" + referenceIndex);
		reference.setContents(document);
		reference.setDigestMethodAlgorithm(params.getDigestAlgorithm());
		if (reference.getContents().getMimeType() == MimeType.XML && params.isEmbedXML()) {
			DSSTransform xmlTransform = new DSSTransform();
			xmlTransform.setAlgorithm(Canonicalizer.ALGO_ID_C14N_OMIT_COMMENTS);
			reference.setTransforms(Arrays.asList(xmlTransform));
		} else {
			DSSTransform base64Transform = new DSSTransform();
			base64Transform.setAlgorithm(CanonicalizationMethod.BASE64);
			reference.setTransforms(Arrays.asList(base64Transform));
		}
		return reference;
	}

	@Override
	protected DSSDocument transformReference(final DSSReference reference) {
		return reference.getContents();
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
		final String signatureValueBase64Encoded = Utils.toBase64(signatureValueBytes);
		final Text signatureValueNode = documentDom.createTextNode(signatureValueBase64Encoded);
		signatureValueDom.appendChild(signatureValueNode);

		final List<DSSReference> references = params.getReferences();
		for (final DSSReference reference : references) {

			final String id = reference.getUri().substring(1);
			// <ds:Object>
			DSSDocument tbsDoc = reference.getContents();
			if (tbsDoc.getMimeType() == MimeType.XML && params.isEmbedXML()) {
				try {
					Document doc = DomUtils.buildDOM(reference.getContents().openStream());
					Element root = doc.getDocumentElement();
					Node adopted = documentDom.adoptNode(root);

					final Element dom = documentDom.createElementNS(XMLSignature.XMLNS, DS_OBJECT);
					dom.appendChild(adopted);
					signatureDom.appendChild(dom);
					dom.setAttribute(ID, id);

				} catch (Exception e) {
					throw new DSSException(e);
				}
			} else {
				final String base64EncodedOriginalDocument = Utils.toBase64(DSSUtils.toByteArray(reference.getContents()));
				final Element objectDom = DomUtils.addTextElement(documentDom, signatureDom, XMLSignature.XMLNS, DS_OBJECT, base64EncodedOriginalDocument);
				objectDom.setAttribute(ID, id);
			}
		}

		byte[] documentBytes = DSSXMLUtils.serializeNode(documentDom);
		final InMemoryDocument inMemoryDocument = new InMemoryDocument(documentBytes);
		inMemoryDocument.setMimeType(MimeType.XML);
		return inMemoryDocument;
	}

}