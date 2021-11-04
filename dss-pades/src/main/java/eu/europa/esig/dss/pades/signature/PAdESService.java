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

import eu.europa.esig.dss.cades.CMSUtils;
import eu.europa.esig.dss.cades.signature.CAdESLevelBaselineT;
import eu.europa.esig.dss.cades.signature.CustomContentSigner;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.TimestampBinary;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.PAdESTimestampParameters;
import eu.europa.esig.dss.pades.SignatureFieldParameters;
import eu.europa.esig.dss.pades.timestamp.PAdESTimestampService;
import eu.europa.esig.dss.pdf.IPdfObjFactory;
import eu.europa.esig.dss.pdf.PDFSignatureService;
import eu.europa.esig.dss.pdf.ServiceLoaderPdfObjFactory;
import eu.europa.esig.dss.signature.AbstractSignatureService;
import eu.europa.esig.dss.signature.SignatureExtension;
import eu.europa.esig.dss.signature.SigningOperation;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.timestamp.TimestampToken;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.SignerInfoGeneratorBuilder;
import org.bouncycastle.tsp.TSPException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.List;
import java.util.Objects;

/**
 * PAdES implementation of the DocumentSignatureService
 */
public class PAdESService extends AbstractSignatureService<PAdESSignatureParameters, PAdESTimestampParameters> {

	private static final long serialVersionUID = -6518552348520127617L;

	private static final Logger LOG = LoggerFactory.getLogger(PAdESService.class);

	/** Builds the CMSSignedData */
	private final PadesCMSSignedDataBuilder padesCMSSignedDataBuilder;

	/** Loads a relevant implementation for signature creation/extension */
	private IPdfObjFactory pdfObjFactory = new ServiceLoaderPdfObjFactory();

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

	/**
	 * Set the IPdfObjFactory. Allow to set the used implementation. Cannot be null.
	 * 
	 * @param pdfObjFactory
	 *                      the implementation to be used.
	 */
	public void setPdfObjFactory(IPdfObjFactory pdfObjFactory) {
		Objects.requireNonNull(pdfObjFactory, "PdfObjFactory is null");
		this.pdfObjFactory = pdfObjFactory;
	}

	private SignatureExtension<PAdESSignatureParameters> getExtensionProfile(SignatureLevel signatureLevel) {
		Objects.requireNonNull(signatureLevel, "SignatureLevel must be defined!");
		switch (signatureLevel) {
			case PAdES_BASELINE_B:
				return null;
			case PAdES_BASELINE_T:
				return new PAdESLevelBaselineT(tspSource, certificateVerifier, pdfObjFactory);
			case PAdES_BASELINE_LT:
				return new PAdESLevelBaselineLT(tspSource, certificateVerifier, pdfObjFactory);
			case PAdES_BASELINE_LTA:
				return new PAdESLevelBaselineLTA(tspSource, certificateVerifier, pdfObjFactory);
			default:
				throw new IllegalArgumentException("Signature format '" + signatureLevel + "' not supported");
		}
	}

	@Override
	public TimestampToken getContentTimestamp(DSSDocument toSignDocument, PAdESSignatureParameters parameters) {
		final PDFSignatureService pdfSignatureService = pdfObjFactory.newContentTimestampService();
		final DigestAlgorithm digestAlgorithm = parameters.getContentTimestampParameters().getDigestAlgorithm();
		final byte[] messageDigest = pdfSignatureService.digest(toSignDocument, parameters);
		TimestampBinary timeStampResponse = tspSource.getTimeStampResponse(digestAlgorithm, messageDigest);
		try {
			return new TimestampToken(timeStampResponse.getBytes(), TimestampType.CONTENT_TIMESTAMP);
		} catch (TSPException | IOException | CMSException e) {
			throw new DSSException("Cannot obtain the content timestamp", e);
		}
	}

	@Override
	public ToBeSigned getDataToSign(final DSSDocument toSignDocument, final PAdESSignatureParameters parameters) throws DSSException {
		Objects.requireNonNull(toSignDocument, "toSignDocument cannot be null!");
		Objects.requireNonNull(parameters, "SignatureParameters cannot be null!");

		assertSigningCertificateValid(parameters);

		final SignatureAlgorithm signatureAlgorithm = parameters.getSignatureAlgorithm();
		final CustomContentSigner customContentSigner = new CustomContentSigner(signatureAlgorithm.getJCEId());

		final byte[] messageDigest = computeDocumentDigest(toSignDocument, parameters);

		SignerInfoGeneratorBuilder signerInfoGeneratorBuilder = padesCMSSignedDataBuilder.getSignerInfoGeneratorBuilder(parameters, messageDigest);

		final CMSSignedDataGenerator generator = padesCMSSignedDataBuilder.createCMSSignedDataGenerator(parameters, customContentSigner,
				signerInfoGeneratorBuilder, null);

		final CMSProcessableByteArray content = new CMSProcessableByteArray(messageDigest);

		CMSUtils.generateDetachedCMSSignedData(generator, content);

		final byte[] dataToSign = customContentSigner.getOutputStream().toByteArray();
		return new ToBeSigned(dataToSign);
	}

	/**
	 * Computes digest of the document to be signed
	 *
	 * @param toSignDocument {@link DSSDocument} the to be signed PDF
	 * @param parameters {@link PAdESSignatureParameters}
	 * @return bytes to be signed
	 */
	public byte[] computeDocumentDigest(final DSSDocument toSignDocument, final PAdESSignatureParameters parameters) {
		final PDFSignatureService pdfSignatureService = pdfObjFactory.newPAdESSignatureService();
		return pdfSignatureService.digest(toSignDocument, parameters);
	}

	@Override
	public DSSDocument signDocument(final DSSDocument toSignDocument, final PAdESSignatureParameters parameters, SignatureValue signatureValue)
			throws DSSException {
		Objects.requireNonNull(toSignDocument, "toSignDocument cannot be null!");
		Objects.requireNonNull(parameters, "SignatureParameters cannot be null!");

		assertSigningCertificateValid(parameters);
		signatureValue = ensureSignatureValue(parameters.getSignatureAlgorithm(), signatureValue);

		final byte[] encodedData = generateCMSSignedData(toSignDocument, parameters, signatureValue);
		return signDocumentWithCms(toSignDocument, parameters, encodedData);
	}

	public DSSDocument signDocumentWithCms(final DSSDocument toSignDocument, final PAdESSignatureParameters parameters, final byte[] encodedData)
			throws DSSException {
		Objects.requireNonNull(toSignDocument, "toSignDocument cannot be null!");
		Objects.requireNonNull(parameters, "SignatureParameters cannot be null!");

		assertSigningCertificateValid(parameters);

		final PDFSignatureService pdfSignatureService = pdfObjFactory.newPAdESSignatureService();
		DSSDocument signature = pdfSignatureService.sign(toSignDocument, encodedData, parameters);

		final SignatureLevel signatureLevel = parameters.getSignatureLevel();
		final SignatureExtension<PAdESSignatureParameters> extension = getExtensionProfile(signatureLevel);
		if ((signatureLevel != SignatureLevel.PAdES_BASELINE_B) && (signatureLevel != SignatureLevel.PAdES_BASELINE_T) && (extension != null)) {
			signature = extension.extendSignatures(signature, parameters);
		}

		parameters.reinitDeterministicId();
		signature.setName(getFinalFileName(toSignDocument, SigningOperation.SIGN, parameters.getSignatureLevel()));
		return signature;
	}

	/**
	 * Generates the CMSSignedData
	 *
	 * @param toSignDocument {@link DSSDocument} to be signed
	 * @param parameters {@link PAdESSignatureParameters}
	 * @param signatureValue {@link SignatureValue}
	 * @return byte array representing the CMSSignedData
	 */
	protected byte[] generateCMSSignedData(final DSSDocument toSignDocument, final PAdESSignatureParameters parameters,
										   final SignatureValue signatureValue) {
		final SignatureAlgorithm signatureAlgorithm = parameters.getSignatureAlgorithm();
		final SignatureLevel signatureLevel = parameters.getSignatureLevel();
		Objects.requireNonNull(signatureAlgorithm, "SignatureAlgorithm cannot be null!");
		Objects.requireNonNull(signatureLevel, "SignatureLevel must be defined!");

		final byte[] messageDigest = computeDocumentDigest(toSignDocument, parameters);
		return generateCMSSignedData(messageDigest, parameters, signatureValue);
	}

	/**
	 * Generates the CMSSignedData
	 *
	 * @param messageDigest {@link DSSDocument} digest to sign
	 * @param parameters {@link PAdESSignatureParameters}
	 * @param signatureValue {@link SignatureValue}
	 * @return byte array representing the CMSSignedData
	 */
	public byte[] generateCMSSignedData(final byte[] messageDigest, final PAdESSignatureParameters parameters,
																			final SignatureValue signatureValue) {
		final SignatureAlgorithm signatureAlgorithm = parameters.getSignatureAlgorithm();
		final SignatureLevel signatureLevel = parameters.getSignatureLevel();
		Objects.requireNonNull(signatureAlgorithm, "SignatureAlgorithm cannot be null!");
		Objects.requireNonNull(signatureLevel, "SignatureLevel must be defined!");

		final CustomContentSigner customContentSigner = new CustomContentSigner(signatureAlgorithm.getJCEId(), signatureValue.getValue());

		final SignerInfoGeneratorBuilder signerInfoGeneratorBuilder = padesCMSSignedDataBuilder.getSignerInfoGeneratorBuilder(parameters, messageDigest);

		final CMSSignedDataGenerator generator = padesCMSSignedDataBuilder.createCMSSignedDataGenerator(parameters, customContentSigner,
				signerInfoGeneratorBuilder, null);

		final CMSProcessableByteArray content = new CMSProcessableByteArray(messageDigest);
		CMSSignedData data = CMSUtils.generateDetachedCMSSignedData(generator, content);

		if (signatureLevel != SignatureLevel.PAdES_BASELINE_B) {
			// use an embedded timestamp
			CAdESLevelBaselineT cadesLevelBaselineT = new CAdESLevelBaselineT(tspSource, certificateVerifier);
			data = cadesLevelBaselineT.extendCMSSignatures(data, parameters);
		}

		return DSSASN1Utils.getDEREncoded(data);
	}

	@Override
	public DSSDocument extendDocument(final DSSDocument toExtendDocument, final PAdESSignatureParameters parameters) throws DSSException {
		Objects.requireNonNull(toExtendDocument, "toExtendDocument is not defined!");
		Objects.requireNonNull(parameters, "Cannot extend the signature. SignatureParameters are not defined!");
		if (SignatureLevel.PAdES_BASELINE_B.equals(parameters.getSignatureLevel())) {
			throw new IllegalArgumentException("Cannot extend to PAdES_BASELINE_B");
		}
		
		final SignatureExtension<PAdESSignatureParameters> extension = getExtensionProfile(parameters.getSignatureLevel());
		if (extension != null) {
			DSSDocument extended = extension.extendSignatures(toExtendDocument, parameters);
			extended.setName(getFinalFileName(toExtendDocument, SigningOperation.EXTEND, parameters.getSignatureLevel()));
			return extended;
		}
		return toExtendDocument;
	}

	/**
	 * This method returns not signed signature-fields
	 * 
	 * @param document
	 *            the pdf document
	 * @return the list of empty signature fields
	 */
	public List<String> getAvailableSignatureFields(DSSDocument document) {
		return getAvailableSignatureFields(document, null);
	}

	/**
	 * This method returns not signed signature-fields from an encrypted document
	 * 
	 * @param document
	 *            the pdf document
	 * @param passwordProtection
	 *            the password protection used to create the encrypted document
	 * @return the list of empty signature fields
	 */
	public List<String> getAvailableSignatureFields(DSSDocument document, String passwordProtection) {
		PDFSignatureService pdfSignatureService = pdfObjFactory.newPAdESSignatureService();
		return pdfSignatureService.getAvailableSignatureFields(document, passwordProtection);
	}

	/**
	 * This method allows to add a new signature field to an existing pdf document
	 * 
	 * @param document
	 *            the pdf document
	 * @param parameters
	 *            the parameters with the coordinates,... of the signature field
	 * @return the pdf document with the new added signature field
	 */
	public DSSDocument addNewSignatureField(DSSDocument document, SignatureFieldParameters parameters) {
		return addNewSignatureField(document, parameters, null);
	}

	/**
	 * This method allows to add a new signature field to an encrypted pdf document
	 * 
	 * @param document
	 *            the pdf document
	 * @param parameters
	 *            the parameters with the coordinates,... of the signature field
	 * @param passwordProtection
	 *            the password protection used to create the encrypted document
	 * @return the pdf document with the new added signature field
	 */
	public DSSDocument addNewSignatureField(DSSDocument document, SignatureFieldParameters parameters, String passwordProtection) {
		PDFSignatureService pdfSignatureService = pdfObjFactory.newPAdESSignatureService();
		return pdfSignatureService.addNewSignatureField(document, parameters, passwordProtection);
	}

	@Override
	public DSSDocument timestamp(DSSDocument toTimestampDocument, PAdESTimestampParameters parameters) {
		PAdESExtensionService extensionService = new PAdESExtensionService(certificateVerifier, pdfObjFactory);
		DSSDocument extendedDocument = extensionService.incorporateValidationData(toTimestampDocument, parameters.getPasswordProtection());

		PAdESTimestampService timestampService = new PAdESTimestampService(tspSource, pdfObjFactory.newSignatureTimestampService());
		DSSDocument timestampedDocument = timestampService.timestampDocument(extendedDocument, parameters);
		timestampedDocument.setName(getFinalFileName(toTimestampDocument, SigningOperation.TIMESTAMP, null));
		return timestampedDocument;
	}

}
