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
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.validation.PAdESSignature;
import eu.europa.esig.dss.pades.validation.PDFDocumentValidator;
import eu.europa.esig.dss.pdf.DSSDictionaryCallback;
import eu.europa.esig.dss.pdf.IPdfObjFactory;
import eu.europa.esig.dss.pdf.PDFSignatureService;
import eu.europa.esig.dss.signature.SignatureExtension;
import eu.europa.esig.dss.spi.x509.tsp.TSPSource;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.DefaultAdvancedSignature.ValidationDataForInclusion;
import eu.europa.esig.dss.validation.ValidationContext;
import eu.europa.esig.dss.validation.timestamp.TimestampToken;

/**
 * PAdES Baseline LT signature
 */
class PAdESLevelBaselineLT implements SignatureExtension<PAdESSignatureParameters> {

	private final CertificateVerifier certificateVerifier;
	private final TSPSource tspSource;
	private final IPdfObjFactory pdfObjectFactory;

	PAdESLevelBaselineLT(final TSPSource tspSource, final CertificateVerifier certificateVerifier, final IPdfObjFactory pdfObjectFactory) {
		this.certificateVerifier = certificateVerifier;
		this.tspSource = tspSource;
		this.pdfObjectFactory = pdfObjectFactory;
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
		if (Utils.isCollectionEmpty(signatures)) {
			throw new DSSException("No signature to be extended");
		}

		for (final AdvancedSignature signature : signatures) {
			if (isRequireDocumentTimestamp(signature)) {
				final PAdESLevelBaselineT padesLevelBaselineT = new PAdESLevelBaselineT(tspSource, pdfObjectFactory);
				document = padesLevelBaselineT.extendSignatures(document, parameters);

				pdfDocumentValidator = new PDFDocumentValidator(document);
				pdfDocumentValidator.setCertificateVerifier(certificateVerifier);
				break;
			}
		}

		signatures = pdfDocumentValidator.getSignatures();

		// create DSS dictionary (order is important to know the original object
		// streams)
		List<DSSDictionaryCallback> callbacks = new LinkedList<>();
		for (final AdvancedSignature signature : signatures) {
			if (signature instanceof PAdESSignature) {
				PAdESSignature padesSignature = (PAdESSignature) signature;
				assertExtendSignaturePossible(padesSignature);
				callbacks.add(validate(padesSignature));
			}
		}

		final PDFSignatureService signatureService = pdfObjectFactory.newPAdESSignatureService();
		return signatureService.addDssDictionary(document, callbacks);

	}

	private boolean isRequireDocumentTimestamp(AdvancedSignature signature) {
		List<TimestampToken> signatureTimestamps = signature.getSignatureTimestamps();
		List<TimestampToken> archiveTimestamps = signature.getArchiveTimestamps();
		return Utils.isCollectionEmpty(signatureTimestamps) && Utils.isCollectionEmpty(archiveTimestamps);
	}
	
	private void assertExtendSignaturePossible(PAdESSignature padesSignature) throws DSSException {
		if (padesSignature.areAllSelfSignedCertificates()) {
			throw new DSSException("Cannot extend the signature. The signature contains only self-signed certificate chains!");
		}
	}

	protected DSSDictionaryCallback validate(PAdESSignature signature) {

		final ValidationContext validationContext = signature.getSignatureValidationContext(certificateVerifier);
		final ValidationDataForInclusion validationDataForInclusion = signature.getValidationDataForInclusion(validationContext);
		
		DSSDictionaryCallback validationCallback = new DSSDictionaryCallback();
		validationCallback.setSignature(signature);

		Set<CertificateToken> certificatesForInclusion = validationDataForInclusion.certificateTokens;
		certificatesForInclusion.addAll(signature.getCompleteCertificateSource().getAllCertificateTokens());
		// DSS dictionary includes current certs + discovered with AIA,...
		validationCallback.setCertificates(certificatesForInclusion);

		validationCallback.setCrls(validationDataForInclusion.crlTokens);
		validationCallback.setOcsps(validationDataForInclusion.ocspTokens);

		return validationCallback;
	}

}
