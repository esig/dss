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
import eu.europa.ec.markt.dss.DSSXMLUtils;
import eu.europa.ec.markt.dss.DigestAlgorithm;
import eu.europa.ec.markt.dss.EncryptionAlgorithm;
import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.exception.DSSNullException;
import eu.europa.ec.markt.dss.parameter.DSSReference;
import eu.europa.ec.markt.dss.parameter.SignatureParameters;
import eu.europa.ec.markt.dss.signature.DSSDocument;
import eu.europa.ec.markt.dss.signature.InMemoryDocument;
import eu.europa.ec.markt.dss.signature.ProfileParameters;
import eu.europa.ec.markt.dss.signature.token.DSSPrivateKeyEntry;
import eu.europa.ec.markt.dss.validation102853.AdvancedSignature;
import eu.europa.ec.markt.dss.validation102853.CertificateVerifier;
import eu.europa.ec.markt.dss.validation102853.xades.XAdESSignature;
import eu.europa.ec.markt.dss.validation102853.xades.XPathQueryHolder;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

/**
 * This class provides the methods required to countersign a given signature and extend the existing signature with the generated
 * countersignature.
 */
public class CounterSignatureBuilder extends ExtensionBuilder implements XAdESSignatureExtension {

	protected CounterSignatureBuilder(final CertificateVerifier certificateVerifier) {
		super(certificateVerifier);
	}

	@Override
	public InMemoryDocument extendSignatures(final DSSDocument dssDocument, final SignatureParameters params) throws DSSException {
		return null;
	}

	/**
	 * Method that performs the countersigning of a given signed document or signature
	 * @param dssDocument the document to countersign
	 * @param parameters the (counter) signature parameters, containing the ID of the signature to be countersigned
	 * @return the countersigned document or signature
	 */
	public DSSDocument counterSignDocument(final DSSDocument dssDocument, final SignatureParameters parameters) {

		//retrieve signature based on ID provided in parameters
		final Document toCounterSignDom = DSSXMLUtils.buildDOM(dssDocument);
		final NodeList signatures = toCounterSignDom.getElementsByTagName(XPathQueryHolder.XMLE_SIGNATURE);
		Element signatureElement = null;
		for (int i = 0; i < signatures.getLength(); i++) {
			signatureElement = (Element) signatures.item(i);
			if (parameters.getToCounterSignSignatureId().equals(signatureElement.getAttribute("Id"))) {
				break;
			}
		}

		if (signatureElement == null) {
			throw new DSSNullException(Element.class);
		}

		Element signatureValueElement = DSSXMLUtils.getElement(signatureElement, xPathQueryHolder.XPATH_SIGNATURE_VALUE);

		if (signatureValueElement == null) {
			throw new DSSNullException(Element.class);
		}

		final EncryptionAlgorithm encryptionAlgorithm = parameters.getEncryptionAlgorithm();
		final DigestAlgorithm digestAlgorithm = parameters.getDigestAlgorithm();
		final DSSPrivateKeyEntry dssPrivateKeyEntry = parameters.getPrivateKeyEntry();

		byte[] dataToSign = DSSXMLUtils.canonicalizeSubtree(CanonicalizationMethod.INCLUSIVE, signatureValueElement);
		byte[] counterSignatureValue = parameters.getSigningToken().sign(dataToSign, digestAlgorithm, dssPrivateKeyEntry);

		//build full signature
		final XAdESLevelBaselineB profile;
		final ProfileParameters context = parameters.getContext();
		if (context.getProfile() != null) {

			profile = context.getProfile();
		} else {

			profile = new XAdESLevelBaselineB(certificateVerifier);
		}
		SignatureBuilder builder = parameters.getContext().getBuilder();
		if (builder != null) {

			builder = parameters.getContext().getBuilder();
		} else {

			builder = SignatureBuilder.getSignatureBuilder(parameters, dssDocument);
		}

		//signature under XML form
		DSSDocument counterSignatureDocument = builder.signDocument(counterSignatureValue);
		//get counterSignature from the DSSDocument


		//DSSDocument counterSignedDocument = incorporateCounterSignature(counterSignature, parameters.getToCounterSignSignatureId());

		return null;
	}

	/**
	 * This method incorporates a given countersignature in the current signature XML DOM.
	 * TODO
	 * @param counterSignatureDocument the newly obtained signature, as a DSSDocument
	 * @param counterSignedSignatureId the id of the signature that was countersigned
	 */
	private void incorporateCounterSignature(DSSDocument counterSignatureDocument, String counterSignedSignatureId) {

		Document counterSignatureDom = DSSXMLUtils.buildDOM(counterSignatureDocument);
		//incorporate references...


		Element unsignedSignaturePropertiesElement = DSSXMLUtils.getElement(currentSignatureDom, xPathQueryHolder.XPATH_UNSIGNED_SIGNATURE_PROPERTIES);
		Element counterSignatureElement = DSSXMLUtils.addElement(documentDom, unsignedSignaturePropertiesDom, XMLSignature.XMLNS, "xades:CounterSignature");
		counterSignatureElement.appendChild(counterSignatureDom);

		//build DSSReference elements
		//1. 	Need reference with ID "Reference-XXX", type "http://uri.etsi.org/01903#CountersignedSignature",
		// 		URI -> id of countersigned signatureValue
		//		Add transforms
		//		Add DigestMethod
		//		Add DigestValue
		DSSReference csReference = new DSSReference();
//		csReference.setDigestMethod(signature.getDigestAlgorithm().getXmlId());
		csReference.setId(""); //need to be "Reference-XXX" -> deterministic ID ?
		csReference.setTransforms(null); //no idea what to put here ???
		csReference.setType(xPathQueryHolder.XADES_COUNTERSIGNED_SIGNATURE);
		csReference.setUri(counterSignedSignatureId); //add "#" in front ?

		//2. 	Need reference of type "http://uri.etsi.org/01903#SignedProperties", URI -> id of related SignedProperties
		//		Add DigestValue
//		DSSReference spReference = new DSSReference();
//		spReference.setDigestMethod();
//		spReference.setType(xPathQueryHolder.XADES_SIGNED_PROPERTIES);
//		spReference.setUri(); //Id of countersignature + "-SignedProperties" at end


		//3. 	Need reference with URI -> id of related KeyInfo
		//		Add DigestValue
//		DSSReference kiReference = new DSSReference();
//		kiReference.setUri(); //Id of countersignature + "-KeyInfo" at end
//		kiReference.setDigestMethod();

		//build Countersignature element
		//1. 	Build Signature element
		//2. 	Add references (see above) to signature element
		//3. 	Embed signature in <xades:CounterSignature> element



		//add countersignature element to current XML DOM
	}


}
