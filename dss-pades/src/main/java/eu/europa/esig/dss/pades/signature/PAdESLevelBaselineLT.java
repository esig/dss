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

import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.exception.IllegalInputException;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.validation.PAdESSignature;
import eu.europa.esig.dss.pades.validation.PDFDocumentValidator;
import eu.europa.esig.dss.pades.validation.PdfValidationDataContainer;
import eu.europa.esig.dss.pdf.IPdfObjFactory;
import eu.europa.esig.dss.pdf.PDFSignatureService;
import eu.europa.esig.dss.spi.x509.tsp.TSPSource;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.timestamp.TimestampToken;

import java.util.List;

import static eu.europa.esig.dss.enumerations.SignatureLevel.PAdES_BASELINE_LT;

/**
 * PAdES Baseline LT signature
 */
class PAdESLevelBaselineLT extends PAdESLevelBaselineT {

	/**
	 * The default constructor
	 *
	 * @param tspSource {@link TSPSource} to use
	 * @param certificateVerifier {@link CertificateVerifier}
	 * @param pdfObjectFactory {@link IPdfObjFactory}
	 */
	PAdESLevelBaselineLT(final TSPSource tspSource, final CertificateVerifier certificateVerifier,
						 final IPdfObjFactory pdfObjectFactory) {
		super(tspSource, certificateVerifier, pdfObjectFactory);
	}

	@Override
	protected DSSDocument extendSignatures(DSSDocument document, PDFDocumentValidator documentValidator,
										   PAdESSignatureParameters parameters) {
		final DSSDocument extendedDocument = super.extendSignatures(document, documentValidator, parameters);
		boolean tLevelAdded = extendedDocument != document;
		if (tLevelAdded) { // check if T-level has been added
			documentValidator = getPDFDocumentValidator(extendedDocument, parameters);
		}

		List<AdvancedSignature> signatures = documentValidator.getSignatures();
		assertExtendSignaturePossible(signatures, parameters, tLevelAdded);

		List<TimestampToken> detachedTimestamps = documentValidator.getDetachedTimestamps();
		PdfValidationDataContainer validationData = documentValidator.getValidationData(signatures, detachedTimestamps);

		final PDFSignatureService signatureService = getPAdESSignatureService();
		return signatureService.addDssDictionary(extendedDocument, validationData, parameters.getPasswordProtection());
	}

	/**
	 * This method returns a {@code PDFSignatureService} to be used for a DSS Dictionary addition
	 *
	 * @return {@link PDFSignatureService}
	 */
	private PDFSignatureService getPAdESSignatureService() {
		return pdfObjectFactory.newPAdESSignatureService();
	}

	private void assertExtendSignaturePossible(List<AdvancedSignature> signatures, PAdESSignatureParameters parameters,
											   boolean tLevelAdded) {
		for (AdvancedSignature signature : signatures) {
			final PAdESSignature padesSignature = (PAdESSignature) signature;
			final SignatureLevel signatureLevel = parameters.getSignatureLevel();
			if (!tLevelAdded && PAdES_BASELINE_LT.equals(signatureLevel) && padesSignature.hasLTAProfile()) {
				throw new IllegalInputException(String.format(
						"Cannot extend signature to '%s'. The signature is already extended with LTA level.", signatureLevel));
			} else if (padesSignature.getCertificateSource().getNumberOfCertificates() == 0) {
				throw new IllegalInputException("Cannot extend signature. The signature does not contain certificates.");
			} else if (padesSignature.areAllSelfSignedCertificates()) {
				throw new IllegalInputException("Cannot extend the signature. The signature contains only self-signed certificate chains!");
			}
		}
	}

}
