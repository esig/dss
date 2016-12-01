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

import org.apache.xml.security.Init;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.SignaturePackaging;
import eu.europa.esig.dss.SignatureValue;
import eu.europa.esig.dss.SigningOperation;
import eu.europa.esig.dss.ToBeSigned;
import eu.europa.esig.dss.signature.AbstractSignatureService;
import eu.europa.esig.dss.signature.MultipleDocumentsSignatureService;
import eu.europa.esig.dss.signature.SignatureExtension;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.xades.DSSReference;
import eu.europa.esig.dss.xades.ProfileParameters;
import eu.europa.esig.dss.xades.ProfileParameters.Operation;
import eu.europa.esig.dss.xades.SignatureProfile;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;

/**
 * XAdES implementation of DocumentSignatureService
 */
public class XAdESService extends AbstractSignatureService<XAdESSignatureParameters> implements MultipleDocumentsSignatureService<XAdESSignatureParameters> {

	static {
		Init.init();
	}

	private static final Logger LOG = LoggerFactory.getLogger(XAdESService.class);

	/**
	 * This is the constructor to create an instance of the {@code XAdESService}. A certificate verifier must be
	 * provided.
	 *
	 * @param certificateVerifier
	 *            {@code CertificateVerifier} provides information on the sources to be used in the validation process
	 *            in the context of a signature.
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
	public ToBeSigned getDataToSign(List<DSSDocument> toSignDocuments, XAdESSignatureParameters parameters) throws DSSException {
		assertMultiDocumentsAllowed(parameters);
		DSSDocument firstDoc = toSignDocuments.get(0);
		XAdESSignatureBuilder xadesSignatureBuilder = XAdESSignatureBuilder.getSignatureBuilder(parameters, firstDoc, certificateVerifier);
		List<DSSReference> references = xadesSignatureBuilder.createReferencesForDocuments(toSignDocuments);
		parameters.setReferences(references);
		return getDataToSign(firstDoc, parameters);
	}

	/**
	 * Only DETACHED and ENVELOPING signatures are allowed
	 * 
	 * @param parameters
	 */
	private void assertMultiDocumentsAllowed(XAdESSignatureParameters parameters) {
		SignaturePackaging signaturePackaging = parameters.getSignaturePackaging();
		if (signaturePackaging == null || SignaturePackaging.ENVELOPED == signaturePackaging) {
			throw new DSSException("Not supported operation (only DETACHED or ENVELOPING are allowed)");
		}
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
				List<DSSDocument> detachedContents = new ArrayList<DSSDocument>();
				detachedContents.add(toSignDocument);
				parameters.setDetachedContents(detachedContents);
			}
			final DSSDocument dssExtendedDocument = extension.extendSignatures(signedDoc, parameters);
			// The deterministic id is reset between two consecutive signing operations. It prevents having two
			// signatures with the same Id within the
			// same document.
			parameters.reinitDeterministicId();
			dssExtendedDocument.setName(DSSUtils.getFinalFileName(toSignDocument, SigningOperation.SIGN, parameters.getSignatureLevel()));
			return dssExtendedDocument;
		}

		parameters.reinitDeterministicId();
		signedDoc.setName(DSSUtils.getFinalFileName(toSignDocument, SigningOperation.SIGN, parameters.getSignatureLevel()));
		return signedDoc;
	}

	@Override
	public DSSDocument signDocument(List<DSSDocument> toSignDocuments, XAdESSignatureParameters parameters, SignatureValue signatureValue) throws DSSException {
		assertMultiDocumentsAllowed(parameters);
		DSSDocument firstDoc = toSignDocuments.get(0);
		XAdESSignatureBuilder xadesSignatureBuilder = XAdESSignatureBuilder.getSignatureBuilder(parameters, firstDoc, certificateVerifier);
		List<DSSReference> references = xadesSignatureBuilder.createReferencesForDocuments(toSignDocuments);
		parameters.setReferences(references);
		return signDocument(firstDoc, parameters, signatureValue);
	}

	@Override
	public DSSDocument extendDocument(final DSSDocument toExtendDocument, final XAdESSignatureParameters parameters) throws DSSException {
		parameters.getContext().setOperationKind(Operation.EXTENDING);
		final SignatureExtension<XAdESSignatureParameters> extension = getExtensionProfile(parameters);
		if (extension != null) {
			final DSSDocument dssDocument = extension.extendSignatures(toExtendDocument, parameters);
			dssDocument.setName(DSSUtils.getFinalFileName(toExtendDocument, SigningOperation.EXTEND, parameters.getSignatureLevel()));
			return dssDocument;
		}
		throw new DSSException("Cannot extend to " + parameters.getSignatureLevel().name());
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
