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
import eu.europa.esig.dss.pades.validation.PDFDocumentValidator;
import eu.europa.esig.dss.pades.validation.PdfValidationDataContainer;
import eu.europa.esig.dss.pdf.IPdfObjFactory;
import eu.europa.esig.dss.pdf.PDFSignatureService;
import eu.europa.esig.dss.spi.x509.tsp.TSPSource;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.timestamp.TimestampToken;

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
		if (extendedDocument != document) { // check if T-level has been added
			documentValidator = getPDFDocumentValidator(document, parameters);
		}

		List<AdvancedSignature> signatures = documentValidator.getSignatures();
		assertExtendSignaturePossible(signatures);

		List<TimestampToken> detachedTimestamps = documentValidator.getDetachedTimestamps();
		PdfValidationDataContainer validationData = documentValidator.getValidationData(signatures, detachedTimestamps);

		final PDFSignatureService signatureService = newPdfSignatureService();
		return signatureService.addDssDictionary(extendedDocument, validationData, parameters.getPasswordProtection());
	}

	private void assertExtendSignaturePossible(List<AdvancedSignature> signatures) {
		for (AdvancedSignature signature : signatures) {
			if (signature.areAllSelfSignedCertificates()) {
				throw new IllegalInputException("Cannot extend the signature. " +
						"The signature contains only self-signed certificate chains!");
			}
		}
	}

}
