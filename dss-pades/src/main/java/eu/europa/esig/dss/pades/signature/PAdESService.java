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
package eu.europa.esig.dss.pades.signature;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;

import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.SignerInfoGeneratorBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.MimeType;
import eu.europa.esig.dss.SignatureAlgorithm;
import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.SignatureValue;
import eu.europa.esig.dss.SigningOperation;
import eu.europa.esig.dss.ToBeSigned;
import eu.europa.esig.dss.cades.CMSUtils;
import eu.europa.esig.dss.cades.signature.CAdESLevelBaselineT;
import eu.europa.esig.dss.cades.signature.CustomContentSigner;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pdf.PDFSignatureService;
import eu.europa.esig.dss.pdf.PdfObjFactory;
import eu.europa.esig.dss.signature.AbstractSignatureService;
import eu.europa.esig.dss.signature.SignatureExtension;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.CertificateVerifier;

/**
 * PAdES implementation of the DocumentSignatureService
 */
public class PAdESService extends AbstractSignatureService<PAdESSignatureParameters> {

	private static final Logger LOG = LoggerFactory.getLogger(PAdESService.class);

	private final PadesCMSSignedDataBuilder padesCMSSignedDataBuilder;

	/**
	 * This is the constructor to create an instance of the {@code PAdESService}. A certificate verifier must be
	 * provided.
	 *
	 * @param certificateVerifier
	 *            {@code CertificateVerifier} provides information on the sources to be used in the validation process
	 *            in the context of a signature.
	 */
	public PAdESService(CertificateVerifier certificateVerifier) {

		super(certificateVerifier);
		padesCMSSignedDataBuilder = new PadesCMSSignedDataBuilder(certificateVerifier);
		LOG.debug("+ PAdESService created");
	}

	private SignatureExtension<PAdESSignatureParameters> getExtensionProfile(SignatureLevel signatureLevel) {
		switch (signatureLevel) {
		case PAdES_BASELINE_B:
			return null;
		case PAdES_BASELINE_T:
			return new PAdESLevelBaselineT(tspSource);
		case PAdES_BASELINE_LT:
			return new PAdESLevelBaselineLT(tspSource, certificateVerifier);
		case PAdES_BASELINE_LTA:
			return new PAdESLevelBaselineLTA(tspSource, certificateVerifier);
		default:
			throw new IllegalArgumentException("Signature format '" + signatureLevel + "' not supported");
		}
	}

	@Override
	public ToBeSigned getDataToSign(final DSSDocument toSignDocument, final PAdESSignatureParameters parameters) throws DSSException {

		assertSigningDateInCertificateValidityRange(parameters);

		final SignatureAlgorithm signatureAlgorithm = parameters.getSignatureAlgorithm();
		final CustomContentSigner customContentSigner = new CustomContentSigner(signatureAlgorithm.getJCEId());

		final PDFSignatureService pdfSignatureService = PdfObjFactory.getInstance().newPAdESSignatureService();
		final InputStream inputStream = toSignDocument.openStream();
		final byte[] messageDigest = pdfSignatureService.digest(inputStream, parameters, parameters.getDigestAlgorithm());
		Utils.closeQuietly(inputStream);

		SignerInfoGeneratorBuilder signerInfoGeneratorBuilder = padesCMSSignedDataBuilder.getSignerInfoGeneratorBuilder(parameters, messageDigest);

		final CMSSignedDataGenerator generator = padesCMSSignedDataBuilder.createCMSSignedDataGenerator(parameters, customContentSigner,
				signerInfoGeneratorBuilder, null);

		final CMSProcessableByteArray content = new CMSProcessableByteArray(messageDigest);

		CMSUtils.generateDetachedCMSSignedData(generator, content);

		final byte[] dataToSign = customContentSigner.getOutputStream().toByteArray();
		return new ToBeSigned(dataToSign);
	}

	@Override
	public DSSDocument signDocument(final DSSDocument toSignDocument, final PAdESSignatureParameters parameters, final SignatureValue signatureValue)
			throws DSSException {

		assertSigningDateInCertificateValidityRange(parameters);

		final SignatureAlgorithm signatureAlgorithm = parameters.getSignatureAlgorithm();
		final CustomContentSigner customContentSigner = new CustomContentSigner(signatureAlgorithm.getJCEId(), signatureValue.getValue());

		final PDFSignatureService pdfSignatureService = PdfObjFactory.getInstance().newPAdESSignatureService();
		InputStream inputStream = toSignDocument.openStream();
		final byte[] messageDigest = pdfSignatureService.digest(inputStream, parameters, parameters.getDigestAlgorithm());
		Utils.closeQuietly(inputStream);

		final SignerInfoGeneratorBuilder signerInfoGeneratorBuilder = padesCMSSignedDataBuilder.getSignerInfoGeneratorBuilder(parameters, messageDigest);

		final CMSSignedDataGenerator generator = padesCMSSignedDataBuilder.createCMSSignedDataGenerator(parameters, customContentSigner,
				signerInfoGeneratorBuilder, null);

		final CMSProcessableByteArray content = new CMSProcessableByteArray(messageDigest);
		CMSSignedData data = CMSUtils.generateDetachedCMSSignedData(generator, content);

		final SignatureLevel signatureLevel = parameters.getSignatureLevel();
		if (signatureLevel != SignatureLevel.PAdES_BASELINE_B) {
			// use an embedded timestamp
			CAdESLevelBaselineT cadesLevelBaselineT = new CAdESLevelBaselineT(tspSource, false);
			data = cadesLevelBaselineT.extendCMSSignatures(data, parameters);
		}

		final ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
		final byte[] encodedData = CMSUtils.getEncoded(data);
		inputStream = toSignDocument.openStream();
		pdfSignatureService.sign(inputStream, encodedData, byteArrayOutputStream, parameters, parameters.getDigestAlgorithm());
		Utils.closeQuietly(inputStream);
		DSSDocument signature = new InMemoryDocument(byteArrayOutputStream.toByteArray());
		signature.setMimeType(MimeType.PDF);

		final SignatureExtension<PAdESSignatureParameters> extension = getExtensionProfile(signatureLevel);
		if ((signatureLevel != SignatureLevel.PAdES_BASELINE_B) && (signatureLevel != SignatureLevel.PAdES_BASELINE_T) && (extension != null)) {
			signature = extension.extendSignatures(signature, parameters);
		}

		parameters.reinitDeterministicId();
		signature.setName(DSSUtils.getFinalFileName(toSignDocument, SigningOperation.SIGN, parameters.getSignatureLevel()));
		return signature;
	}

	@Override
	public DSSDocument extendDocument(DSSDocument original, PAdESSignatureParameters parameters) throws DSSException {
		final SignatureExtension<PAdESSignatureParameters> extension = getExtensionProfile(parameters.getSignatureLevel());
		if (extension != null) {
			DSSDocument extended = extension.extendSignatures(original, parameters);
			extended.setName(DSSUtils.getFinalFileName(original, SigningOperation.EXTEND, parameters.getSignatureLevel()));
			return extended;
		}
		return original;
	}

}