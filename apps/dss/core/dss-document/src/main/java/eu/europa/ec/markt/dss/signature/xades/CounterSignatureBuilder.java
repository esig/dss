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

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
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
 * This class provides the methods required to countersign a given signature and extend the existing signature with the generated
 * countersignature.
 */
public class CounterSignatureBuilder extends SignatureBuilder {

	private Element toCounterSignSignatureElement;
	private Document toCounterSignDocument;
	private String signatureValueId;

	public CounterSignatureBuilder(final SignatureParameters parameters, final DSSDocument toCounterSignDocument) {
		super(parameters, toCounterSignDocument);
	}

	public void setSignatureValueId(String signatureValueId) {
		this.signatureValueId = signatureValueId;
	}

	public void setToCounterSignSignatureElement(Element toCounterSignSignatureElement) {
		this.toCounterSignSignatureElement = toCounterSignSignatureElement;
	}

	public Document getToCounterSignDocument() {
		return toCounterSignDocument;
	}

	public void setToCounterSignDocument(Document toCounterSignDocument) {
		this.toCounterSignDocument = toCounterSignDocument;
	}

	public void incorporateReference1() {
	}

	@Override
	protected DSSDocument canonicalizeReference(DSSReference reference) {
		return null;
	}

	@Override
	public byte[] build() throws DSSException {

		documentDom = DSSXMLUtils.buildDOM();
		deterministicId = params.getDeterministicId();
		reference2CanonicalizationMethod = CanonicalizationMethod.EXCLUSIVE;
		signedInfoCanonicalizationMethod = CanonicalizationMethod.EXCLUSIVE;

		incorporateSignatureDom();
		incorporateSignedInfo();

		incorporateSignatureValue();
		incorporateKeyInfo();

		incorporateObject();

		incorporateReference1();
		incorporateReference2();

		DSSReference counterSignatureReference = new DSSReference();
		counterSignatureReference.setDigestMethod(params.getDigestAlgorithm().getXmlId());
		counterSignatureReference.setType(xPathQueryHolder.XADES_COUNTERSIGNED_SIGNATURE);
		counterSignatureReference.setUri("#" + signatureValueId);

		DSSTransform dssTransform = new DSSTransform();
		dssTransform.setAlgorithm(HTTP_WWW_W3_ORG_TR_1999_REC_XPATH_19991116);
		List<DSSTransform> transforms = new ArrayList<DSSTransform>();
		transforms.add(dssTransform);

		counterSignatureReference.setTransforms(transforms);

		incorporateReference(counterSignatureReference);

		byte[] canonicalizedSignedInfo = DSSXMLUtils.canonicalizeSubtree(signedInfoCanonicalizationMethod, signedInfoDom);
		if (LOG.isTraceEnabled()) {
			LOG.trace("Canonicalized SignedInfo         --> {}", new String(canonicalizedSignedInfo));
		}
		built = true;
		return canonicalizedSignedInfo;
	}

	/**
	 * This method incorporates a given countersignature value in the current signature XML DOM.
	 *
	 * @param counterSignatureValue
	 * @return
	 */
	public DSSDocument signDocument(byte[] counterSignatureValue) {

		if (!built) {
			build();
		}

		unsignedSignaturePropertiesDom = DSSXMLUtils.getElement(toCounterSignSignatureElement, xPathQueryHolder.XPATH_UNSIGNED_SIGNATURE_PROPERTIES);
		final Document ownerDocument = toCounterSignSignatureElement.getOwnerDocument();
		if (unsignedSignaturePropertiesDom == null) {

			Element unsignedPropertiesDom = DSSXMLUtils.getElement(toCounterSignSignatureElement, xPathQueryHolder.XPATH_UNSIGNED_PROPERTIES);
			if (unsignedPropertiesDom == null) {

				final Element qualifyingPropertiesDom = DSSXMLUtils.getElement(toCounterSignSignatureElement, xPathQueryHolder.XPATH_QUALIFYING_PROPERTIES);
				unsignedPropertiesDom = DSSXMLUtils.addElement(ownerDocument, qualifyingPropertiesDom, XMLSignature.XMLNS, DS_UNSIGNED_PROPERTIES);
			}
			unsignedSignaturePropertiesDom = DSSXMLUtils.addElement(ownerDocument, unsignedPropertiesDom, XMLSignature.XMLNS, DS_UNSIGNED_SIGNATURE_PROPERTIES);
		}

		final Element counterSignatureElement = DSSXMLUtils.addElement(ownerDocument, unsignedSignaturePropertiesDom, XMLSignature.XMLNS, DS_COUNTER_SIGNATURE);
		final EncryptionAlgorithm encryptionAlgorithm = params.getEncryptionAlgorithm();
		final byte[] signatureValueBytes = DSSSignatureUtils.convertToXmlDSig(encryptionAlgorithm, counterSignatureValue);
		final String signatureValueBase64Encoded = DSSUtils.base64Encode(signatureValueBytes);
		final Text signatureValueNode = documentDom.createTextNode(signatureValueBase64Encoded);
		signatureValueDom.appendChild(signatureValueNode);

		final Node importedNode = unsignedSignaturePropertiesDom.getOwnerDocument().importNode(documentDom.getFirstChild(), true);
		counterSignatureElement.appendChild(importedNode);

		final byte[] documentBytes = DSSXMLUtils.transformDomToByteArray(toCounterSignDocument);
		return new InMemoryDocument(documentBytes);
	}

	public void setParams(SignatureParameters parameters) {
		params = parameters;
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
