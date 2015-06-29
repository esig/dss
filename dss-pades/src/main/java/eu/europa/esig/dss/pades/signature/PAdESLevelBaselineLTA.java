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

import java.util.List;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.validation.PDFDocumentValidator;
import eu.europa.esig.dss.signature.SignatureExtension;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.x509.tsp.TSPSource;

/**
 * PAdES Baseline LTA signature
 */
class PAdESLevelBaselineLTA implements SignatureExtension<PAdESSignatureParameters> {

	private final PAdESLevelBaselineLT padesLevelBaselineLT;
	private final PAdESLevelBaselineT padesLevelBaselineT;
	private final CertificateVerifier certificateVerifier;

	public PAdESLevelBaselineLTA(TSPSource tspSource, CertificateVerifier certificateVerifier) {
		padesLevelBaselineLT = new PAdESLevelBaselineLT(tspSource, certificateVerifier);
		padesLevelBaselineT = new PAdESLevelBaselineT(tspSource);
		this.certificateVerifier = certificateVerifier;
	}

	@Override
	public DSSDocument extendSignatures(DSSDocument document, PAdESSignatureParameters parameters) throws DSSException {

		// check if needed to extends with PAdESLevelBaselineLT
		final PDFDocumentValidator pdfDocumentValidator = new PDFDocumentValidator(document);
		pdfDocumentValidator.setCertificateVerifier(certificateVerifier);

		List<AdvancedSignature> signatures = pdfDocumentValidator.getSignatures();
		for (final AdvancedSignature signature : signatures) {
			if (!signature.isDataForSignatureLevelPresent(SignatureLevel.PAdES_BASELINE_LT)) {
				document = padesLevelBaselineLT.extendSignatures(document, parameters);
				break;
			}
		}

		// Will add a Document TimeStamp (not CMS)
		return padesLevelBaselineT.extendSignatures(document, parameters);
	}
}