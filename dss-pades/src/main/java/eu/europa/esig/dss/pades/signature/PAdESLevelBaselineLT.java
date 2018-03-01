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

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.validation.PAdESSignature;
import eu.europa.esig.dss.pades.validation.PDFDocumentValidator;
import eu.europa.esig.dss.pdf.DSSDictionaryCallback;
import eu.europa.esig.dss.pdf.PDFSignatureService;
import eu.europa.esig.dss.pdf.PdfObjFactory;
import eu.europa.esig.dss.signature.SignatureExtension;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.DefaultAdvancedSignature;
import eu.europa.esig.dss.validation.ValidationContext;
import eu.europa.esig.dss.x509.CertificateToken;
import eu.europa.esig.dss.x509.tsp.TSPSource;

/**
 * PAdES Baseline LT signature
 */
class PAdESLevelBaselineLT implements SignatureExtension<PAdESSignatureParameters> {

	private final CertificateVerifier certificateVerifier;
	private final TSPSource tspSource;

	PAdESLevelBaselineLT(final TSPSource tspSource, final CertificateVerifier certificateVerifier) {
		this.certificateVerifier = certificateVerifier;
		this.tspSource = tspSource;
	}

	/**
	 * @param document
	 * @param parameters
	 * @return
	 * @throws IOException
	 */
	@Override
	public DSSDocument extendSignatures(DSSDocument document, final PAdESSignatureParameters parameters) throws DSSException {

		// check if needed to extends with PAdESLevelBaselineT
		PDFDocumentValidator pdfDocumentValidator = new PDFDocumentValidator(document);
		pdfDocumentValidator.setCertificateVerifier(certificateVerifier);

		List<AdvancedSignature> signatures = pdfDocumentValidator.getSignatures();
		for (final AdvancedSignature signature : signatures) {
			if (!signature.isDataForSignatureLevelPresent(SignatureLevel.PAdES_BASELINE_T)) {
				final PAdESLevelBaselineT padesLevelBaselineT = new PAdESLevelBaselineT(tspSource);
				document = padesLevelBaselineT.extendSignatures(document, parameters);

				pdfDocumentValidator = new PDFDocumentValidator(document);
				pdfDocumentValidator.setCertificateVerifier(certificateVerifier);
				break;
			}
		}

		signatures = pdfDocumentValidator.getSignatures();

		// create DSS dictionary
		List<DSSDictionaryCallback> callbacks = new ArrayList<DSSDictionaryCallback>();
		for (final AdvancedSignature signature : signatures) {
			if (signature instanceof PAdESSignature) {
				callbacks.add(validate((PAdESSignature) signature));
			}
		}

		final PDFSignatureService signatureService = PdfObjFactory.getInstance().newPAdESSignatureService();
		return signatureService.addDssDictionary(document, callbacks);

	}

	private DSSDictionaryCallback validate(PAdESSignature signature) {

		ValidationContext validationContext = signature.getSignatureValidationContext(certificateVerifier);
		DefaultAdvancedSignature.RevocationDataForInclusion revocationsForInclusionInProfileLT = signature.getRevocationDataForInclusion(validationContext);

		DSSDictionaryCallback validationCallback = new DSSDictionaryCallback();
		validationCallback.setSignature(signature);
		validationCallback.setCrls(revocationsForInclusionInProfileLT.crlTokens);
		validationCallback.setOcsps(revocationsForInclusionInProfileLT.ocspTokens);

		Set<CertificateToken> certs = new HashSet<CertificateToken>(signature.getCertificates());
		validationCallback.setCertificates(certs);

		return validationCallback;
	}

}