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

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.Text;

import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.DSSXMLUtils;
import eu.europa.ec.markt.dss.parameter.DSSReference;
import eu.europa.ec.markt.dss.parameter.DSSTransform;
import eu.europa.ec.markt.dss.parameter.SignatureParameters;
import eu.europa.ec.markt.dss.signature.DSSDocument;
import eu.europa.ec.markt.dss.signature.InMemoryDocument;
import eu.europa.ec.markt.dss.signature.MimeType;
import eu.europa.ec.markt.dss.validation102853.xades.XAdESSignature;

import static eu.europa.ec.markt.dss.XAdESNamespaces.XAdES;

/**
 * This class provides the methods required to countersign a given signature and extend the existing signature with the generated
 * countersignature.
 */
public class CounterSignatureBuilder extends EnvelopedSignatureBuilder {

	private XAdESSignature toCounterSignXadesSignature;

	public CounterSignatureBuilder(final DSSDocument toCounterSignDocument, final XAdESSignature toCounterSignXadesSignature, final SignatureParameters parameters) {

		super(parameters, toCounterSignDocument);
		this.toCounterSignXadesSignature = toCounterSignXadesSignature;
	}

	@Override
	protected List<DSSReference> createDefaultReferences() {

		final List<DSSReference> references = new ArrayList<DSSReference>();

		final DSSReference dssReference = new DSSReference();
		dssReference.setId("cs-r-id-1");
		dssReference.setUri("#" + params.getToCounterSignSignatureValueId());
		dssReference.setType(xPathQueryHolder.XADES_COUNTERSIGNED_SIGNATURE);
		dssReference.setContents(detachedDocument);
		dssReference.setDigestMethodAlgorithm(params.getDigestAlgorithm());

		final List<DSSTransform> dssTransformList = new ArrayList<DSSTransform>();

		DSSTransform dssTransform = new DSSTransform();
		dssTransform.setAlgorithm(CanonicalizationMethod.EXCLUSIVE);
		dssTransform.setPerform(true);
		dssTransformList.add(dssTransform);

		dssReference.setTransforms(dssTransformList);

		references.add(dssReference);

		return references;
	}

	/**
	 * This method incorporates a given countersignature value in the current signature XML DOM.
	 *
	 * @param counterSignatureValue
	 * @return
	 */
	public DSSDocument signDocument(final byte[] counterSignatureValue) {

		if (!built) {
			build();
		}

		unsignedSignaturePropertiesDom = toCounterSignXadesSignature.getUnsignedSignaturePropertiesDom();
		final Document ownerDocument = toCounterSignXadesSignature.getSignatureElement().getOwnerDocument();
		if (unsignedSignaturePropertiesDom == null) {

			Element unsignedPropertiesDom = toCounterSignXadesSignature.getUnsignedPropertiesDom();
			if (unsignedPropertiesDom == null) {

				final Element qualifyingPropertiesDom = toCounterSignXadesSignature.getQualifyingPropertiesDom();
				// TODO-Vin (15/09/2014): add null chzck
				unsignedPropertiesDom = DSSXMLUtils.addElement(ownerDocument, qualifyingPropertiesDom, XAdES, XADES_UNSIGNED_PROPERTIES);
			}
			unsignedSignaturePropertiesDom = DSSXMLUtils.addElement(ownerDocument, unsignedPropertiesDom, XAdES, XADES_UNSIGNED_SIGNATURE_PROPERTIES);
		}

		final Element counterSignatureElement = DSSXMLUtils.addElement(ownerDocument, unsignedSignaturePropertiesDom, XAdES, XADES_COUNTER_SIGNATURE);
		final String signatureValueBase64Encoded = DSSUtils.base64Encode(counterSignatureValue);
		final Text signatureValueNode = documentDom.createTextNode(signatureValueBase64Encoded);
		signatureValueDom.appendChild(signatureValueNode);

		final Node importedNode = ownerDocument.importNode(documentDom.getFirstChild(), true);
		counterSignatureElement.appendChild(importedNode);

		final byte[] documentBytes = DSSXMLUtils.transformDomToByteArray(ownerDocument);
		final InMemoryDocument inMemoryDocument = new InMemoryDocument(documentBytes);
		inMemoryDocument.setMimeType(MimeType.XML);
		return inMemoryDocument;
	}
}
