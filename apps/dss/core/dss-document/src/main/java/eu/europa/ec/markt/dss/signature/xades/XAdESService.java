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

import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.XMLSignature;

import org.apache.xml.security.Init;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import eu.europa.ec.markt.dss.DSSXMLUtils;
import eu.europa.ec.markt.dss.DigestAlgorithm;
import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.exception.DSSNullException;
import eu.europa.ec.markt.dss.parameter.SignatureParameters;
import eu.europa.ec.markt.dss.signature.AbstractSignatureService;
import eu.europa.ec.markt.dss.signature.DSSDocument;
import eu.europa.ec.markt.dss.signature.ProfileParameters;
import eu.europa.ec.markt.dss.signature.ProfileParameters.Operation;
import eu.europa.ec.markt.dss.signature.SignatureExtension;
import eu.europa.ec.markt.dss.signature.SignatureLevel;
import eu.europa.ec.markt.dss.signature.SignaturePackaging;
import eu.europa.ec.markt.dss.signature.token.DSSPrivateKeyEntry;
import eu.europa.ec.markt.dss.signature.token.SignatureTokenConnection;
import eu.europa.ec.markt.dss.validation102853.CertificateVerifier;
import eu.europa.ec.markt.dss.validation102853.xades.XAdESSignature;
import eu.europa.ec.markt.dss.validation102853.xades.XPathQueryHolder;

/**
 * XAdES implementation of DocumentSignatureService
 *
 * @version $Revision$ - $Date$
 */

public class XAdESService extends AbstractSignatureService {

	static {

		Init.init();
	}

	private static final Logger LOG = LoggerFactory.getLogger(XAdESService.class);

	/**
	 * This is the constructor to create an instance of the {@code XAdESService}. A certificate verifier must be provided.
	 *
	 * @param certificateVerifier {@code CertificateVerifier} provides information on the sources to be used in the validation process in the context of a signature.
	 */
	public XAdESService(final CertificateVerifier certificateVerifier) {

		super(certificateVerifier);
		LOG.debug("+ XAdESService created");
	}

	@Override
	public byte[] getDataToSign(final DSSDocument toSignDocument, final SignatureParameters parameters) throws DSSException {

		assertSigningDateInCertificateValidityRange(parameters);

		final XAdESLevelBaselineB levelBaselineB = new XAdESLevelBaselineB(certificateVerifier);
		final byte[] dataToSign = levelBaselineB.getDataToSign(toSignDocument, parameters);
		parameters.getContext().setProfile(levelBaselineB);
		return dataToSign;
	}

	@Override
	public DSSDocument signDocument(final DSSDocument toSignDocument, final SignatureParameters parameters, final byte[] signatureValue) throws DSSException {

		if (parameters.getSignatureLevel() == null) {
			throw new DSSNullException(SignatureLevel.class);
		}
		assertSigningDateInCertificateValidityRange(parameters);
		parameters.getContext().setOperationKind(Operation.SIGNING);
		final XAdESLevelBaselineB profile;
		final ProfileParameters context = parameters.getContext();
		if (context.getProfile() != null) {

			profile = context.getProfile();
		} else {

			profile = new XAdESLevelBaselineB(certificateVerifier);
		}
		final DSSDocument signedDoc = profile.signDocument(toSignDocument, parameters, signatureValue);
		final SignatureExtension extension = getExtensionProfile(parameters);
		if (extension != null) {

			if (SignaturePackaging.DETACHED.equals(parameters.getSignaturePackaging())) {

				parameters.setDetachedContent(toSignDocument);
			}
			final DSSDocument dssExtendedDocument = extension.extendSignatures(signedDoc, parameters);
			// The deterministic id is reset between two consecutive signing operations. It prevents having two signatures with the same Id within the same document.
			parameters.setDeterministicId(null);
			return dssExtendedDocument;
		}
		parameters.setDeterministicId(null);
		return signedDoc;
	}

	@Override
	public DSSDocument signDocument(final DSSDocument toSignDocument, final SignatureParameters parameters) throws DSSException {

		if (parameters.getSignatureLevel() == null) {
			throw new DSSNullException(SignatureLevel.class);
		}
		final SignatureTokenConnection signingToken = parameters.getSigningToken();
		if (signingToken == null) {
			throw new DSSNullException(SignatureTokenConnection.class);
		}

		parameters.getContext().setOperationKind(Operation.SIGNING);

		final XAdESLevelBaselineB profile = new XAdESLevelBaselineB(certificateVerifier);
		final byte[] dataToSign = profile.getDataToSign(toSignDocument, parameters);
		parameters.getContext().setProfile(profile);

		final DigestAlgorithm digestAlgorithm = parameters.getDigestAlgorithm();
		final DSSPrivateKeyEntry dssPrivateKeyEntry = parameters.getPrivateKeyEntry();
		final byte[] signatureValue = signingToken.sign(dataToSign, digestAlgorithm, dssPrivateKeyEntry);
		final DSSDocument dssDocument = signDocument(toSignDocument, parameters, signatureValue);
		return dssDocument;
	}

	@Override
	public DSSDocument extendDocument(final DSSDocument toExtendDocument, final SignatureParameters parameters) throws DSSException {

		parameters.getContext().setOperationKind(Operation.EXTENDING);
		final SignatureExtension extension = getExtensionProfile(parameters);
		if (extension != null) {

			final DSSDocument dssDocument = extension.extendSignatures(toExtendDocument, parameters);
			return dssDocument;
		}
		throw new DSSException("Cannot extend to " + parameters.getSignatureLevel().name());
	}

	public DSSDocument counterSignDocument(final DSSDocument toCounterSignDocument, final SignatureParameters parameters) throws DSSException {

		if (parameters.getSignatureLevel() == null) {
			throw new DSSNullException(SignatureLevel.class);
		}

		final SignatureTokenConnection signingToken = parameters.getSigningToken();

		if (signingToken == null) {
			throw new DSSNullException(SignatureTokenConnection.class);
		}

		final Document toCounterSignDom = DSSXMLUtils.buildDOM(toCounterSignDocument);
		final XAdESSignature toCounterSignSignature = new XAdESSignature(toCounterSignDom.getDocumentElement(), null);
		DSSXMLUtils.recursiveIdBrowse(toCounterSignDom.getDocumentElement());
		toCounterSignSignature.recursiveNamespaceBrowser(toCounterSignSignature.getSignatureElement());

		if (parameters.getToCountersignXPathQueryHolder() != null) {
			toCounterSignSignature.addXPathQueryHolder(parameters.getToCountersignXPathQueryHolder());
		}

		//Retrieve signature element to countersign
		final Element toSignSignatureElement = DSSXMLUtils.getElementById(toCounterSignDom, parameters.getToCounterSignSignatureId(), XMLSignature.XMLNS, "Signature");
		parameters.getContext().setOperationKind(Operation.COUNTERSIGNING);

		final XPathQueryHolder xPathQueryHolder = toCounterSignSignature.getXPathQueryHolder();
		final Element signatureValueElement = DSSXMLUtils.getElement(toSignSignatureElement, xPathQueryHolder.XPATH_SIGNATURE_VALUE);

		if (signatureValueElement == null) {
			throw new DSSNullException(Element.class);
		}

		final DigestAlgorithm digestAlgorithm = parameters.getDigestAlgorithm();
		final DSSPrivateKeyEntry dssPrivateKeyEntry = parameters.getPrivateKeyEntry();

		byte[] dataToSign = DSSXMLUtils.canonicalizeSubtree(CanonicalizationMethod.INCLUSIVE, signatureValueElement);
		byte[] counterSignatureValue = parameters.getSigningToken().sign(dataToSign, digestAlgorithm, dssPrivateKeyEntry);

		final CounterSignatureBuilder counterSignatureBuilder = new CounterSignatureBuilder(parameters, toCounterSignDocument);
		counterSignatureBuilder.setToCounterSignSignatureElement(toSignSignatureElement);
		counterSignatureBuilder.setToCounterSignSignatureValueElement(signatureValueElement);
		counterSignatureBuilder.setParams(parameters);
		counterSignatureBuilder.setToCounterSignDocument(toCounterSignDom);
		counterSignatureBuilder.setSignatureValueId(signatureValueElement.getAttribute("Id"));
		DSSDocument countersignatureDocument = counterSignatureBuilder.signDocument(counterSignatureValue);

		return countersignatureDocument;
	}

	/**
	 * The choice of profile according to the passed parameter.
	 *
	 * @param parameters
	 * @return
	 */
	private SignatureExtension getExtensionProfile(final SignatureParameters parameters) {

		switch (parameters.getSignatureLevel()) {
			case XAdES_BASELINE_B:

				return null;
			case XAdES_BASELINE_T:

				final XAdESLevelBaselineT extensionT = new XAdESLevelBaselineT(certificateVerifier);
				extensionT.setTspSource(tspSource);
				return extensionT;
			case XAdES_C:

				final XAdESLevelC extensionC = new XAdESLevelC(certificateVerifier);
				extensionC.setTspSource(tspSource);
				return extensionC;
			case XAdES_X:

				final XAdESLevelX extensionX = new XAdESLevelX(certificateVerifier);
				extensionX.setTspSource(tspSource);
				return extensionX;
			case XAdES_XL:

				final XAdESLevelXL extensionXL = new XAdESLevelXL(certificateVerifier);
				extensionXL.setTspSource(tspSource);
				return extensionXL;
			case XAdES_A:

				final XAdESLevelA extensionA = new XAdESLevelA(certificateVerifier);
				extensionA.setTspSource(tspSource);
				return extensionA;
			case XAdES_BASELINE_LT:

				final XAdESLevelBaselineLT extensionLT = new XAdESLevelBaselineLT(certificateVerifier);
				extensionLT.setTspSource(tspSource);
				return extensionLT;
			case XAdES_BASELINE_LTA:

				final XAdESLevelBaselineLTA extensionLTA = new XAdESLevelBaselineLTA(certificateVerifier);
				extensionLTA.setTspSource(tspSource);
				return extensionLTA;
			default:

				throw new DSSException("Unsupported signature format " + parameters.getSignatureLevel());
		}
	}
}
