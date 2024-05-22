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
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.validation.PDFDocumentValidator;
import eu.europa.esig.dss.pades.validation.PdfValidationDataContainer;
import eu.europa.esig.dss.pdf.IPdfObjFactory;
import eu.europa.esig.dss.pdf.PDFSignatureService;
import eu.europa.esig.dss.signature.SignatureRequirementsChecker;
import eu.europa.esig.dss.spi.x509.tsp.TSPSource;
import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;

import java.util.List;

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

		final SignatureRequirementsChecker signatureRequirementsChecker =
				new PAdESSignatureRequirementsChecker(certificateVerifier, parameters);
		if (!tLevelAdded && SignatureLevel.PAdES_BASELINE_LT.equals(parameters.getSignatureLevel())) {
			signatureRequirementsChecker.assertExtendToLTLevelPossible(signatures);
		}
		signatureRequirementsChecker.assertSignaturesValid(signatures);
		signatureRequirementsChecker.assertCertificateChainValidForLTLevel(signatures);

		List<TimestampToken> detachedTimestamps = documentValidator.getDetachedTimestamps();
		PdfValidationDataContainer validationData = documentValidator.getValidationData(signatures, detachedTimestamps);

		final PDFSignatureService signatureService = getPAdESSignatureService();
		return signatureService.addDssDictionary(extendedDocument, validationData, parameters.getPasswordProtection(), parameters.isIncludeVRIDictionary());
	}

	/**
	 * This method returns a {@code PDFSignatureService} to be used for a DSS Dictionary addition
	 *
	 * @return {@link PDFSignatureService}
	 */
	private PDFSignatureService getPAdESSignatureService() {
		return pdfObjectFactory.newPAdESSignatureService();
	}

}
