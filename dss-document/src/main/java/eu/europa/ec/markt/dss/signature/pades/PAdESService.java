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
package eu.europa.ec.markt.dss.signature.pades;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;

import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.SignerInfoGeneratorBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.ec.markt.dss.DSSASN1Utils;
import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.SignatureAlgorithm;
import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.exception.DSSNullException;
import eu.europa.ec.markt.dss.parameter.SignatureParameters;
import eu.europa.ec.markt.dss.signature.AbstractSignatureService;
import eu.europa.ec.markt.dss.signature.DSSDocument;
import eu.europa.ec.markt.dss.signature.InMemoryDocument;
import eu.europa.ec.markt.dss.signature.MimeType;
import eu.europa.ec.markt.dss.signature.SignatureExtension;
import eu.europa.ec.markt.dss.signature.SignatureLevel;
import eu.europa.ec.markt.dss.signature.cades.CAdESLevelBaselineT;
import eu.europa.ec.markt.dss.signature.cades.CustomContentSigner;
import eu.europa.ec.markt.dss.signature.pdf.PDFSignatureService;
import eu.europa.ec.markt.dss.signature.pdf.PdfObjFactory;
import eu.europa.ec.markt.dss.signature.token.SignatureTokenConnection;
import eu.europa.ec.markt.dss.validation102853.CertificateVerifier;

/**
 * PAdES implementation of the DocumentSignatureService
 *
 *
 */

public class PAdESService extends AbstractSignatureService {

	private static final Logger LOG = LoggerFactory.getLogger(PAdESService.class);

	private final PadesCMSSignedDataBuilder padesCMSSignedDataBuilder;

	/**
	 * This is the constructor to create an instance of the {@code PAdESService}. A certificate verifier must be provided.
	 *
	 * @param certificateVerifier {@code CertificateVerifier} provides information on the sources to be used in the validation process in the context of a signature.
	 */
	public PAdESService(CertificateVerifier certificateVerifier) {

		super(certificateVerifier);
		padesCMSSignedDataBuilder = new PadesCMSSignedDataBuilder(certificateVerifier);
		LOG.debug("+ PAdESService created");
	}

	private SignatureExtension getExtensionProfile(SignatureParameters parameters) {

		switch (parameters.getSignatureLevel()) {
			case PAdES_BASELINE_B:
				return null;
			case PAdES_BASELINE_T:
				return new PAdESLevelBaselineT(tspSource, certificateVerifier);
			case PAdES_BASELINE_LT:
				return new PAdESLevelBaselineLT(tspSource, certificateVerifier);
			case PAdES_BASELINE_LTA:
				return new PAdESLevelBaselineLTA(tspSource, certificateVerifier);
			default:
				throw new IllegalArgumentException("Signature format '" + parameters.getSignatureLevel() + "' not supported");
		}
	}

	@Override
	public byte[] getDataToSign(final DSSDocument toSignDocument, final SignatureParameters parameters) throws DSSException {

		assertSigningDateInCertificateValidityRange(parameters);

		final SignatureAlgorithm signatureAlgorithm = parameters.getSignatureAlgorithm();
		final CustomContentSigner customContentSigner = new CustomContentSigner(signatureAlgorithm.getJCEId());

		final PDFSignatureService pdfSignatureService = PdfObjFactory.getInstance().newPAdESSignatureService();
		final InputStream inputStream = toSignDocument.openStream();
		final byte[] messageDigest = pdfSignatureService.digest(inputStream, parameters, parameters.getDigestAlgorithm());
		DSSUtils.closeQuietly(inputStream);

		SignerInfoGeneratorBuilder signerInfoGeneratorBuilder = padesCMSSignedDataBuilder.getSignerInfoGeneratorBuilder(parameters, messageDigest);

		final CMSSignedDataGenerator generator = padesCMSSignedDataBuilder.createCMSSignedDataGenerator(parameters, customContentSigner, signerInfoGeneratorBuilder, null);

		final CMSProcessableByteArray content = new CMSProcessableByteArray(messageDigest);

		DSSASN1Utils.generateCMSSignedData(generator, content, false);

		final byte[] dataToSign = customContentSigner.getOutputStream().toByteArray();
		return dataToSign;
	}

	@Override
	public DSSDocument signDocument(final DSSDocument toSignDocument, final SignatureParameters parameters, final byte[] signatureValue) throws DSSException {

		assertSigningDateInCertificateValidityRange(parameters);
		try {
			final SignatureAlgorithm signatureAlgorithm = parameters.getSignatureAlgorithm();
			final CustomContentSigner customContentSigner = new CustomContentSigner(signatureAlgorithm.getJCEId(), signatureValue);

			final PDFSignatureService pdfSignatureService = PdfObjFactory.getInstance().newPAdESSignatureService();
			InputStream inputStream = toSignDocument.openStream();
			final byte[] messageDigest = pdfSignatureService.digest(inputStream, parameters, parameters.getDigestAlgorithm());
			DSSUtils.closeQuietly(inputStream);

			final SignerInfoGeneratorBuilder signerInfoGeneratorBuilder = padesCMSSignedDataBuilder.getSignerInfoGeneratorBuilder(parameters, messageDigest);

			final CMSSignedDataGenerator generator = padesCMSSignedDataBuilder.createCMSSignedDataGenerator(parameters, customContentSigner, signerInfoGeneratorBuilder, null);

			final CMSProcessableByteArray content = new CMSProcessableByteArray(messageDigest);
			final boolean encapsulate = false;
			CMSSignedData data = generator.generate(content, encapsulate);

			final SignatureLevel signatureLevel = parameters.getSignatureLevel();
			if (signatureLevel != SignatureLevel.PAdES_BASELINE_B) {
				// use an embedded timestamp
				CAdESLevelBaselineT cadesLevelBaselineT = new CAdESLevelBaselineT(tspSource, certificateVerifier, false);
				data = cadesLevelBaselineT.extendCMSSignatures(data, parameters);
			}

			final ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
			final byte[] encodedData = DSSASN1Utils.getEncoded(data);
			inputStream = toSignDocument.openStream();
			pdfSignatureService.sign(inputStream, encodedData, byteArrayOutputStream, parameters, parameters.getDigestAlgorithm());
			DSSUtils.closeQuietly(inputStream);
			final DSSDocument signature;
			if (DSSUtils.isEmpty(toSignDocument.getName())) {
				signature = new InMemoryDocument(byteArrayOutputStream.toByteArray(), null, MimeType.PDF);
			} else {
				signature = new InMemoryDocument(byteArrayOutputStream.toByteArray(), toSignDocument.getName(), MimeType.PDF);
			}

			final SignatureExtension extension = getExtensionProfile(parameters);
			if (signatureLevel != SignatureLevel.PAdES_BASELINE_B && signatureLevel != SignatureLevel.PAdES_BASELINE_T && extension != null) {
				final DSSDocument extendSignature = extension.extendSignatures(signature, parameters);
				parameters.setDeterministicId(null);
				return extendSignature;
			} else {
				parameters.setDeterministicId(null);
				return signature;
			}
		} catch (CMSException e) {
			throw new DSSException(e);
		}
	}

	@Override
	public DSSDocument extendDocument(DSSDocument toExtendDocument, SignatureParameters parameters) throws DSSException {

		final SignatureExtension extension = getExtensionProfile(parameters);
		if (extension != null) {
			return extension.extendSignatures(toExtendDocument, parameters);
		}
		return toExtendDocument;
	}

	@Override
	public DSSDocument signDocument(final DSSDocument toSignDocument, final SignatureParameters parameters) throws DSSException {

		final SignatureTokenConnection token = parameters.getSigningToken();
		if (token == null) {
			throw new DSSNullException(SignatureTokenConnection.class, "", "The connection through the available API to the SSCD must be set.");
		}
		final byte[] dataToSign = getDataToSign(toSignDocument, parameters);
		final byte[] signatureValue = token.sign(dataToSign, parameters.getDigestAlgorithm(), parameters.getPrivateKeyEntry());
		final DSSDocument dssDocument = signDocument(toSignDocument, parameters, signatureValue);
		return dssDocument;
	}
}
