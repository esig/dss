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

import eu.europa.esig.dss.exception.IllegalInputException;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.PAdESTimestampParameters;
import eu.europa.esig.dss.pades.timestamp.PAdESTimestampService;
import eu.europa.esig.dss.pades.validation.PAdESSignature;
import eu.europa.esig.dss.pades.validation.PDFDocumentValidator;
import eu.europa.esig.dss.pdf.IPdfObjFactory;
import eu.europa.esig.dss.pdf.PDFSignatureService;
import eu.europa.esig.dss.signature.SignatureExtension;
import eu.europa.esig.dss.signature.SignatureRequirementsChecker;
import eu.europa.esig.dss.spi.x509.tsp.TSPSource;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.CertificateVerifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.Objects;

import static eu.europa.esig.dss.enumerations.SignatureLevel.PAdES_BASELINE_T;

/**
 * PAdES Baseline T signature
 *
 */
class PAdESLevelBaselineT implements SignatureExtension<PAdESSignatureParameters> {

	private static final Logger LOG = LoggerFactory.getLogger(PAdESLevelBaselineT.class);

	/** The TSPSource to obtain a timestamp */
	private final TSPSource tspSource;

	/** The used CertificateVerifier */
	protected final CertificateVerifier certificateVerifier;

	/** The used implementation for processing of a PDF document */
	protected final IPdfObjFactory pdfObjectFactory;

	/**
	 * The default constructor
	 *
	 * @param tspSource {@link TSPSource}
	 * @param certificateVerifier {@link CertificateVerifier}
	 * @param pdfObjectFactory {@link IPdfObjFactory}
	 */
	protected PAdESLevelBaselineT(TSPSource tspSource, CertificateVerifier certificateVerifier, IPdfObjFactory pdfObjectFactory) {
		Objects.requireNonNull(tspSource, "TSPSource shall be defined!");
		Objects.requireNonNull(certificateVerifier, "CertificateVerifier shall be defined!");
		Objects.requireNonNull(pdfObjectFactory, "pdfObjectFactory shall be defined!");
		this.tspSource = tspSource;
		this.certificateVerifier = certificateVerifier;
		this.pdfObjectFactory = pdfObjectFactory;
	}

	@Override
	public DSSDocument extendSignatures(final DSSDocument document, final PAdESSignatureParameters params) {
		Objects.requireNonNull(document, "DSSDocument cannot be null!");
		Objects.requireNonNull(params, "SignatureParameters cannot be null!");
		// Will add a DocumentTimeStamp. signature-timestamp (CMS) is impossible to add while extending
		PDFDocumentValidator pdfDocumentValidator = getPDFDocumentValidator(document, params);
		return extendSignatures(document, pdfDocumentValidator, params);
	}

	/**
	 * This method performs a document extension
	 *
	 * @param document {@link DSSDocument}
	 * @param documentValidator {@link PDFDocumentValidator}
	 * @param parameters {@link PAdESSignatureParameters}
	 * @return {@link DSSDocument} extended document
	 */
	protected DSSDocument extendSignatures(final DSSDocument document, final PDFDocumentValidator documentValidator,
										   final PAdESSignatureParameters parameters) {
		List<AdvancedSignature> signatures = documentValidator.getSignatures();
		if (Utils.isCollectionEmpty(signatures)) {
			throw new IllegalInputException("No signatures found to be extended!");
		}

		if (isTLevelExtensionRequired(parameters, signatures)) {
			final SignatureRequirementsChecker signatureRequirementsChecker =
					new PAdESSignatureRequirementsChecker(certificateVerifier, parameters);
			
			signatureRequirementsChecker.assertExtendToTLevelPossible(signatures);
			
			signatureRequirementsChecker.assertSignaturesValid(signatures);
			signatureRequirementsChecker.assertSigningCertificateIsValid(signatures);
			
			// Will add a DocumentTimeStamp. signature-timestamp (CMS) is impossible to add while extending
			return timestampDocument(document, parameters.getSignatureTimestampParameters(),
					parameters.getPasswordProtection(), getSignatureTimestampService());

		} else {
			return document;
		}
	}

	/**
	 * This method returns a {@code PDFSignatureService} to be used for a signature timestamp creation
	 *
	 * @return {@link PDFSignatureService}
	 */
	private PDFSignatureService getSignatureTimestampService() {
		return pdfObjectFactory.newSignatureTimestampService();
	}

	/**
	 * Timestamp document
	 *
	 * @param document {@link DSSDocument} to timestamp
	 * @param timestampParameters {@link PAdESTimestampParameters}
	 * @param pwd password if required
	 * @param pdfSignatureService {@link PDFSignatureService} to be used
	 * @return {@link DSSDocument} timestamped
	 */
	protected DSSDocument timestampDocument(final DSSDocument document,
											final PAdESTimestampParameters timestampParameters, final char[] pwd,
											final PDFSignatureService pdfSignatureService) {
		PAdESTimestampService padesTimestampService = new PAdESTimestampService(tspSource, pdfSignatureService);
		timestampParameters.setPasswordProtection(pwd);
		return padesTimestampService.timestampDocument(document, timestampParameters);
	}

	/**
	 * Returns a document validator instance
	 *
	 * @param document {@link DSSDocument} document to be validated
	 * @param parameters {@link PAdESSignatureParameters} used to create/extend the signature(s)
	 * @return {@link PDFDocumentValidator}
	 */
	protected PDFDocumentValidator getPDFDocumentValidator(DSSDocument document, PAdESSignatureParameters parameters) {
		PDFDocumentValidator pdfDocumentValidator = new PDFDocumentValidator(document);
		pdfDocumentValidator.setCertificateVerifier(certificateVerifier);
		pdfDocumentValidator.setPasswordProtection(parameters.getPasswordProtection());
		pdfDocumentValidator.setPdfObjFactory(pdfObjectFactory);
		return pdfDocumentValidator;
	}

	private boolean isTLevelExtensionRequired(PAdESSignatureParameters parameters, List<AdvancedSignature> signatures) {
		boolean tLevelExtensionRequired = false;
		for (AdvancedSignature signature : signatures) {
			PAdESSignature padesSignature = (PAdESSignature) signature;
			if (requiresDocumentTimestamp(padesSignature, parameters)) {
				tLevelExtensionRequired = true;
			}
		}
		return tLevelExtensionRequired;
	}

	private boolean requiresDocumentTimestamp(PAdESSignature signature, PAdESSignatureParameters signatureParameters) {
		return PAdES_BASELINE_T.equals(signatureParameters.getSignatureLevel()) || !signature.hasTProfile();
	}

}
