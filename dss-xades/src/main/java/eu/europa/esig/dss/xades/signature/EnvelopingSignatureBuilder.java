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

import org.apache.commons.codec.binary.Base64;
import org.w3c.dom.Element;
import org.w3c.dom.Text;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DSSXMLUtils;
import eu.europa.esig.dss.EncryptionAlgorithm;
import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.MimeType;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.xades.DSSReference;
import eu.europa.esig.dss.xades.DSSTransform;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;

/**
 * This class handles the specifics of the enveloping XML signature
 *
 */
class EnvelopingSignatureBuilder extends XAdESSignatureBuilder {

	/**
	 * The default constructor for EnvelopingSignatureBuilder. The enveloped signature uses by default the inclusive
	 * method of canonicalization.
	 *  @param params  The set of parameters relating to the structure and process of the creation or extension of the
	 *                electronic signature.
	 * @param origDoc The original document to sign.
	 * @param certificateVerifier
	 */
	public EnvelopingSignatureBuilder(final XAdESSignatureParameters params, final DSSDocument origDoc, final CertificateVerifier certificateVerifier) {

		super(params, origDoc, certificateVerifier);
		setCanonicalizationMethods(params, CanonicalizationMethod.INCLUSIVE);
	}

	/**
	 * This method creates the first reference (this is a reference to the file to sign) witch is specific for each form
	 * of signature. Here, the value of the URI is an unique identifier to the base64 encoded data (file). The data are
	 * included in the signature XML.
	 *
	 * @throws DSSException
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

		final List<DSSReference> references = new ArrayList<DSSReference>();

		//<ds:Reference Id="signed-data-ref" Type="http://www.w3.org/2000/09/xmldsig#Object" URI="#signed-data-idfc5ff27ee49763d9ba88ba5bbc49f732">
		final DSSReference reference = new DSSReference();
		reference.setId("r-id-1");
		reference.setType(HTTP_WWW_W3_ORG_2000_09_XMLDSIG_OBJECT);
		reference.setUri("#o-id-1");
		reference.setContents(detachedDocument);
		reference.setDigestMethodAlgorithm(params.getDigestAlgorithm());

		final List<DSSTransform> transforms = new ArrayList<DSSTransform>();

		final DSSTransform transform = new DSSTransform();
		transform.setAlgorithm(CanonicalizationMethod.BASE64);

		transforms.add(transform);
		reference.setTransforms(transforms);
		references.add(reference);

		return references;
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
		final String signatureValueBase64Encoded = Base64.encodeBase64String(signatureValueBytes);
		final Text signatureValueNode = documentDom.createTextNode(signatureValueBase64Encoded);
		signatureValueDom.appendChild(signatureValueNode);

		final List<DSSReference> references = params.getReferences();
		for (final DSSReference reference : references) {

			// <ds:Object>
			final String base64EncodedOriginalDocument = reference.getContents().getBase64Encoded();
			final Element objectDom = DSSXMLUtils.addTextElement(documentDom, signatureDom, XMLSignature.XMLNS, DS_OBJECT, base64EncodedOriginalDocument);
			final String id = reference.getUri().substring(1);
			objectDom.setAttribute(ID, id);
		}

		byte[] documentBytes = DSSXMLUtils.transformDomToByteArray(documentDom);
		final InMemoryDocument inMemoryDocument = new InMemoryDocument(documentBytes);
		inMemoryDocument.setMimeType(MimeType.XML);
		return inMemoryDocument;
	}
}