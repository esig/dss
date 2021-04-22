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

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.validation.PDFDocumentValidator;
import eu.europa.esig.dss.pdf.IPdfObjFactory;
import eu.europa.esig.dss.pdf.PDFSignatureService;
import eu.europa.esig.dss.spi.x509.tsp.TSPSource;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.ValidationDataContainer;
import eu.europa.esig.dss.validation.timestamp.TimestampToken;

import java.util.ArrayList;
import java.util.List;

/**
 * PAdES Baseline LT signature
 */
class PAdESLevelBaselineLT extends PAdESLevelBaselineT {

	/** The used CertificateVerifier */
	private final CertificateVerifier certificateVerifier;

	/**
	 * The default constructor
	 *
	 * @param tspSource {@link TSPSource} to use
	 * @param certificateVerifier {@link CertificateVerifier}
	 * @param pdfObjectFactory {@link IPdfObjFactory}
	 */
	PAdESLevelBaselineLT(final TSPSource tspSource, final CertificateVerifier certificateVerifier,
						 final IPdfObjFactory pdfObjectFactory) {
		super(tspSource, pdfObjectFactory);
		this.certificateVerifier = certificateVerifier;
	}

	@Override
	public DSSDocument extendSignatures(DSSDocument document, final PAdESSignatureParameters parameters) {
		assertExtensionPossible(document);

		// check if needed to extends with PAdESLevelBaselineT
		PDFDocumentValidator pdfDocumentValidator = getPDFDocumentValidator(document, parameters);

		List<AdvancedSignature> signatures = pdfDocumentValidator.getSignatures();
		if (Utils.isCollectionEmpty(signatures)) {
			throw new DSSException("No signatures found to be extended!");
		}

		for (final AdvancedSignature signature : signatures) {
			if (requiresDocumentTimestamp(signature)) {
				// extend to T-level
				document = super.extendSignatures(document, parameters);
				pdfDocumentValidator = getPDFDocumentValidator(document, parameters);
				break;
			}
		}

		signatures = pdfDocumentValidator.getSignatures();
		assertExtendSignaturePossible(signatures);

		List<TimestampToken> detachedTimestamps = pdfDocumentValidator.getDetachedTimestamps();
		ValidationDataContainer validationData = pdfDocumentValidator.getValidationData(signatures, detachedTimestamps);

		final PDFSignatureService signatureService = newPdfSignatureService();
		return signatureService.addDssDictionary(document, validationData);

	}
	
	private PDFDocumentValidator getPDFDocumentValidator(DSSDocument document, PAdESSignatureParameters parameters) {
		PDFDocumentValidator pdfDocumentValidator = new PDFDocumentValidator(document);
		pdfDocumentValidator.setCertificateVerifier(certificateVerifier);
		pdfDocumentValidator.setPasswordProtection(parameters.getPasswordProtection());
		return pdfDocumentValidator;
	}

	private boolean requiresDocumentTimestamp(AdvancedSignature signature) {
		List<TimestampToken> timestamps = new ArrayList<>(signature.getSignatureTimestamps());
		timestamps.addAll(signature.getArchiveTimestamps());
		timestamps.addAll(signature.getDocumentTimestamps());
		return Utils.isCollectionEmpty(timestamps);
	}

	private void assertExtendSignaturePossible(List<AdvancedSignature> signatures) {
		for (AdvancedSignature signature : signatures) {
			if (signature.areAllSelfSignedCertificates()) {
				throw new DSSException("Cannot extend the signature. The signature contains only self-signed certificate chains!");
			}
		}
	}

}
