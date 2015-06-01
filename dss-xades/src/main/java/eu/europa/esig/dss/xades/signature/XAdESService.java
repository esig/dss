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

import java.util.List;

import org.apache.commons.lang.StringUtils;
import org.apache.xml.security.Init;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DSSXMLUtils;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.SignatureValue;
import eu.europa.esig.dss.ToBeSigned;
import eu.europa.esig.dss.signature.AbstractSignatureService;
import eu.europa.esig.dss.signature.SignatureExtension;
import eu.europa.esig.dss.signature.SignaturePackaging;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.SignatureTokenConnection;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.xades.ProfileParameters;
import eu.europa.esig.dss.xades.ProfileParameters.Operation;
import eu.europa.esig.dss.xades.SignatureProfile;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.validation.XAdESSignature;
import eu.europa.esig.dss.xades.validation.XMLDocumentValidator;

/**
 * XAdES implementation of DocumentSignatureService
 */
public class XAdESService extends AbstractSignatureService<XAdESSignatureParameters> {

	static {
		Init.init();
	}

	private static final Logger LOG = LoggerFactory.getLogger(XAdESService.class);

	/**
	 * This is the constructor to create an instance of the {@code XAdESService}. A certificate verifier must be provided.
	 *
	 * @param certificateVerifier
	 *            {@code CertificateVerifier} provides information on the sources to be used in the validation process in the context of a signature.
	 */
	public XAdESService(final CertificateVerifier certificateVerifier) {

		super(certificateVerifier);
		LOG.debug("+ XAdESService created");
	}

	@Override
	public ToBeSigned getDataToSign(final DSSDocument toSignDocument, final XAdESSignatureParameters parameters) throws DSSException {

		assertSigningDateInCertificateValidityRange(parameters);

		final XAdESLevelBaselineB levelBaselineB = new XAdESLevelBaselineB(certificateVerifier);
		final byte[] dataToSign = levelBaselineB.getDataToSign(toSignDocument, parameters);
		parameters.getContext().setProfile(levelBaselineB);
		return new ToBeSigned(dataToSign);
	}

	@Override
	public DSSDocument signDocument(final DSSDocument toSignDocument, final XAdESSignatureParameters parameters, SignatureValue signatureValue)
			throws DSSException {

		if (parameters.getSignatureLevel() == null) {
			throw new NullPointerException();
		}
		assertSigningDateInCertificateValidityRange(parameters);
		parameters.getContext().setOperationKind(Operation.SIGNING);
		SignatureProfile profile;
		final ProfileParameters context = parameters.getContext();
		if (context.getProfile() != null) {
			profile = context.getProfile();
		} else {
			profile = new XAdESLevelBaselineB(certificateVerifier);
		}
		final DSSDocument signedDoc = profile.signDocument(toSignDocument, parameters, signatureValue.getValue());
		final SignatureExtension<XAdESSignatureParameters> extension = getExtensionProfile(parameters);
		if (extension != null) {

			if (SignaturePackaging.DETACHED.equals(parameters.getSignaturePackaging())) {

				parameters.setDetachedContent(toSignDocument);
			}
			final DSSDocument dssExtendedDocument = extension.extendSignatures(signedDoc, parameters);
			// The deterministic id is reset between two consecutive signing operations. It prevents having two signatures with the same Id within the
			// same document.
			parameters.reinitDeterministicId();
			return dssExtendedDocument;
		}
		parameters.reinitDeterministicId();
		return signedDoc;
	}

	@Override
	public DSSDocument extendDocument(final DSSDocument toExtendDocument, final XAdESSignatureParameters parameters) throws DSSException {
		parameters.getContext().setOperationKind(Operation.EXTENDING);
		final SignatureExtension<XAdESSignatureParameters> extension = getExtensionProfile(parameters);
		if (extension != null) {

			final DSSDocument dssDocument = extension.extendSignatures(toExtendDocument, parameters);
			return dssDocument;
		}
		throw new DSSException("Cannot extend to " + parameters.getSignatureLevel().name());
	}

	public DSSDocument counterSignDocument(final DSSDocument toCounterSignDocument, final XAdESSignatureParameters parameters, SignatureTokenConnection signingToken, DSSPrivateKeyEntry dssPrivateKeyEntry) throws DSSException {

		if (toCounterSignDocument == null) {
			throw new NullPointerException();
		}
		if (parameters == null) {
			throw new NullPointerException();
		}
		if (parameters.getSignatureLevel() == null) {
			throw new NullPointerException();
		}
		if (signingToken == null) {
			throw new NullPointerException();
		}

		if (dssPrivateKeyEntry == null){
			throw new NullPointerException();
		} else {
			parameters.setSigningCertificate(dssPrivateKeyEntry.getCertificate());
			parameters.setCertificateChain(dssPrivateKeyEntry.getCertificateChain());
		}

		final String toCounterSignSignatureId = parameters.getToCounterSignSignatureId();
		if (StringUtils.isBlank(toCounterSignSignatureId)) {
			throw new DSSException("There is no provided signature id to countersign!");
		}
		final XAdESSignature xadesSignature = getToCountersignSignature(toCounterSignDocument, toCounterSignSignatureId);
		if (xadesSignature == null) {
			throw new DSSException("The signature to countersign not found!");
		}
		final Node signatureValueNode = xadesSignature.getSignatureValue();
		if (signatureValueNode == null) {
			throw new NullPointerException();
		}
		final String signatureValueId = DSSXMLUtils.getIDIdentifier((Element) signatureValueNode);
		if (StringUtils.isBlank(toCounterSignSignatureId)) {
			throw new DSSException("There is no signature-value id to countersign!");
		}
		parameters.setToCounterSignSignatureValueId(signatureValueId);

		final CounterSignatureBuilder counterSignatureBuilder = new CounterSignatureBuilder(toCounterSignDocument, xadesSignature, parameters,
				certificateVerifier);
		final byte[] dataToSign = counterSignatureBuilder.build();

		final DigestAlgorithm digestAlgorithm = parameters.getDigestAlgorithm();
		byte[] counterSignatureValue = signingToken.sign(dataToSign, digestAlgorithm, dssPrivateKeyEntry);

		final DSSDocument counterSignedDocument = counterSignatureBuilder.signDocument(counterSignatureValue);
		// final XMLDocumentValidator xmlDocumentValidator = (XMLDocumentValidator) validator;
		// final Document rootElement = xmlDocumentValidator.getRootElement();
		// final byte[] bytes = DSSXMLUtils.transformDomToByteArray(rootElement);
		// final InMemoryDocument inMemoryDocument = new InMemoryDocument(bytes);
		return counterSignedDocument;
	}

	private XAdESSignature getToCountersignSignature(final DSSDocument toCounterSignDocument, final String toCounterSignSignatureId) {

		final SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(toCounterSignDocument);
		if (!(validator instanceof XMLDocumentValidator)) {
			throw new DSSException("Incompatible signature form!");
		}
		final List<AdvancedSignature> signatures = validator.getSignatures();
		XAdESSignature xadesSignature = null;
		for (final AdvancedSignature signature_ : signatures) {

			final String id = signature_.getId();
			if (toCounterSignSignatureId.equals(id)) {

				xadesSignature = (XAdESSignature) signature_;
				break;
			}
		}
		return xadesSignature;
	}

	/**
	 * The choice of profile according to the passed parameter.
	 *
	 * @param parameters
	 * @return
	 */
	private SignatureExtension<XAdESSignatureParameters> getExtensionProfile(final XAdESSignatureParameters parameters) {

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
