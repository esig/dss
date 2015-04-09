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

import static eu.europa.esig.dss.XAdESNamespaces.XAdES;

import java.util.ArrayList;
import java.util.List;

import javax.xml.crypto.dsig.CanonicalizationMethod;

import org.apache.commons.codec.binary.Base64;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.Text;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSXMLUtils;
import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.MimeType;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.xades.DSSReference;
import eu.europa.esig.dss.xades.DSSTransform;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.validation.XAdESSignature;

/**
 * This class provides the methods required to countersign a given signature and extend the existing signature with the generated
 * countersignature.
 */
public class CounterSignatureBuilder extends EnvelopedSignatureBuilder {

	private XAdESSignature toCounterSignXadesSignature;

	public CounterSignatureBuilder(final DSSDocument toCounterSignDocument, final XAdESSignature toCounterSignXadesSignature, final XAdESSignatureParameters parameters,
			final CertificateVerifier certificateVerifier) {

		super(parameters, toCounterSignDocument, certificateVerifier);
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

	@Override
	protected Document buildRootDocumentDom() {
		return DSSXMLUtils.buildDOM();
	}

	@Override
	protected Node getParentNodeOfSignature() {
		return documentDom;
	}

	/**
	 * This method incorporates a given countersignature value in the current signature XML DOM.
	 *
	 * @param counterSignatureValue
	 * @return
	 */
	@Override
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
				// TODO-Vin (15/09/2014): add null check
				unsignedPropertiesDom = DSSXMLUtils.addElement(ownerDocument, qualifyingPropertiesDom, XAdES, XADES_UNSIGNED_PROPERTIES);
			}
			unsignedSignaturePropertiesDom = DSSXMLUtils.addElement(ownerDocument, unsignedPropertiesDom, XAdES, XADES_UNSIGNED_SIGNATURE_PROPERTIES);
		}

		final Element counterSignatureElement = DSSXMLUtils.addElement(ownerDocument, unsignedSignaturePropertiesDom, XAdES, XADES_COUNTER_SIGNATURE);
		final String signatureValueBase64Encoded = Base64.encodeBase64String(counterSignatureValue);
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
