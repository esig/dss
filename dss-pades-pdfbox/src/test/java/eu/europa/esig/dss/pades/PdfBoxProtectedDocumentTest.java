/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.pades;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.pades.validation.PDFDocumentValidator;
import eu.europa.esig.dss.pades.validation.suite.AbstractPAdESTestValidation;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import org.junit.jupiter.api.Test;

import java.util.Date;

class PdfBoxProtectedDocumentTest extends AbstractPAdESTestValidation {

	private final char[] correctProtectionPhrase = new char[]{ ' ' };

	private final DSSDocument openProtected = new InMemoryDocument(
			getClass().getResourceAsStream("/protected/open_protected.pdf"), "sample.pdf", MimeTypeEnum.PDF);

	// TODO : OpenPdf does not keep the same identifier on protected documents signing
	@Test
	void recreateParamsTest() throws Exception {
		Date date = new Date();
		PAdESService padesService = new PAdESService(getCompleteCertificateVerifier());
		padesService.setTspSource(getGoodTsa());
		
		PAdESSignatureParameters parametersDataToBeSigned = getParameters();
		parametersDataToBeSigned.bLevel().setSigningDate(date);
		parametersDataToBeSigned.setPasswordProtection(correctProtectionPhrase);
		parametersDataToBeSigned.setSignatureLevel(SignatureLevel.PAdES_BASELINE_LTA);
		
		ToBeSigned dataToSign = padesService.getDataToSign(openProtected, parametersDataToBeSigned);

		PAdESSignatureParameters parametersSignatureValue = getParameters();
		parametersSignatureValue.bLevel().setSigningDate(date);
		parametersSignatureValue.setPasswordProtection(correctProtectionPhrase);
		parametersSignatureValue.setSignatureLevel(SignatureLevel.PAdES_BASELINE_LTA);
		
		SignatureValue signatureValue = getToken().sign(dataToSign, parametersSignatureValue.getSignatureAlgorithm(), getPrivateKeyEntry());

		PAdESSignatureParameters parametersSign = getParameters();
		parametersSign.bLevel().setSigningDate(date);
		parametersSign.setPasswordProtection(correctProtectionPhrase);
		parametersSign.setSignatureLevel(SignatureLevel.PAdES_BASELINE_LTA);
		
		DSSDocument signedDocument = padesService.signDocument(openProtected, parametersSign, signatureValue);
		
		PDFDocumentValidator validator = (PDFDocumentValidator) getValidator(signedDocument);
		validator.setPasswordProtection(correctProtectionPhrase);
		
		Reports reports = validator.validateDocument();
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		
		checkBLevelValid(diagnosticData);
		checkTimestamps(diagnosticData);
	}
	
	private PAdESSignatureParameters getParameters() {
		PAdESSignatureParameters signatureParameters = new PAdESSignatureParameters();
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);
		return signatureParameters;
	}
	
	@Override
	protected SignedDocumentValidator getValidator(DSSDocument signedDocument) {
		PDFDocumentValidator validator = new PDFDocumentValidator(signedDocument);
		validator.setCertificateVerifier(getOfflineCertificateVerifier());
		validator.setPasswordProtection(correctProtectionPhrase);
		return validator;
	}
	
	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

	@Override
	protected DSSDocument getSignedDocument() {
		return null;
	}
	
	@Override
	public void validate() {
		// do nothing
	}

}
