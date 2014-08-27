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

import org.w3c.dom.Element;
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

/**
 * This class handles the specifics of the enveloping XML signature
 * <p/>
 * <p/>
 * DISCLAIMER: Project owner DG-MARKT.
 *
 * @author <a href="mailto:dgmarkt.Project-DSS@arhs-developments.com">ARHS Developments</a>
 * @version $Revision: 672 $ - $Date: 2011-05-12 11:59:21 +0200 (Thu, 12 May 2011) $
 */
class EnvelopingSignatureBuilder extends SignatureBuilder {

	/**
	 * The default constructor for EnvelopingSignatureBuilder. The enveloped signature uses by default the inclusive
	 * method of canonicalization.
	 *
	 * @param params  The set of parameters relating to the structure and process of the creation or extension of the
	 *                electronic signature.
	 * @param origDoc The original document to sign.
	 */
	public EnvelopingSignatureBuilder(SignatureParameters params, DSSDocument origDoc) {

		super(params, origDoc);
		signedInfoCanonicalizationMethod = CanonicalizationMethod.INCLUSIVE;
		reference2CanonicalizationMethod = CanonicalizationMethod.INCLUSIVE;
	}

	/**
	 * This method creates the first reference (this is a reference to the file to sign) witch is specific for each form
	 * of signature. Here, the value of the URI is an unique identifier to the base64 encoded data (file). The data are
	 * included in the signature XML.
	 *
	 * @throws DSSException
	 */
	@Override
	protected void incorporateReference1() throws DSSException {

		final List<DSSReference> references = params.getReferences();
		for (final DSSReference reference : references) {

			incorporateReference(reference);
		}
	}

	@Override
	protected List<DSSReference> createDefaultReference() {

		final List<DSSReference> references = new ArrayList<DSSReference>();

		//<ds:Reference Id="signed-data-ref" Type="http://www.w3.org/2000/09/xmldsig#Object" URI="#signed-data-idfc5ff27ee49763d9ba88ba5bbc49f732">
		final DSSReference reference = new DSSReference();
		reference.setId("r-id-1");
		reference.setType(HTTP_WWW_W3_ORG_2000_09_XMLDSIG_OBJECT);
		reference.setUri("#o-id-1");
		reference.setContents(originalDocument);

		final List<DSSTransform> transforms = new ArrayList<DSSTransform>();

		final DSSTransform transform = new DSSTransform();
		transform.setAlgorithm(CanonicalizationMethod.BASE64);

		transforms.add(transform);
		reference.setTransforms(transforms);
		references.add(reference);

		return references;
	}

	@Override
	protected DSSDocument canonicalizeReference(final DSSReference reference) {

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
		final String signatureValueBase64Encoded = DSSUtils.base64Encode(signatureValueBytes);
		final Text signatureValueNode = documentDom.createTextNode(signatureValueBase64Encoded);
		signatureValueDom.appendChild(signatureValueNode);

		final List<DSSReference> references = params.getReferences();
		for (final DSSReference reference : references) {

			// <ds:Object>
			final String base64EncodedOriginalDocument = DSSUtils.base64Encode(reference.getContents());
			final Element objectDom = DSSXMLUtils.addTextElement(documentDom, signatureDom, XMLSignature.XMLNS, DS_OBJECT, base64EncodedOriginalDocument);
			final String id = reference.getUri().substring(1);
			objectDom.setAttribute(ID, id);
		}

		byte[] documentBytes = DSSXMLUtils.transformDomToByteArray(documentDom);
		final InMemoryDocument inMemoryDocument = new InMemoryDocument(documentBytes);
		return inMemoryDocument;
	}
}