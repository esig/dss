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
package eu.europa.esig.dss.cades.signature;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.util.Arrays;

import org.junit.Test;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.DigestDocument;
import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.SignatureValue;
import eu.europa.esig.dss.ToBeSigned;
import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.signature.PKIFactoryAccess;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.validationreport.jaxb.SignatureIdentifierType;
import eu.europa.esig.validationreport.jaxb.SignatureValidationReportType;
import eu.europa.esig.validationreport.jaxb.ValidationReportType;

public class CAdESLevelBDetachedDigestDocumentTest extends PKIFactoryAccess {

	private static final String DOCUMENT_NAME = "test.text";
	private static final DigestAlgorithm USED_DIGEST = DigestAlgorithm.SHA256;

	@Test
	public void testWithCompleteDocument() {
		CAdESService service = getService();
		CAdESSignatureParameters params = getParams();
		DSSDocument completeDocument = getCompleteDocument();

		ToBeSigned toBeSigned = service.getDataToSign(completeDocument, params);
		SignatureValue signatureValue = getToken().sign(toBeSigned, params.getDigestAlgorithm(), getPrivateKeyEntry());
		DSSDocument signedDoc = service.signDocument(completeDocument, params, signatureValue);

		Reports reports = validate(signedDoc, completeDocument);
		validateHashOnly(reports, false, false);
		reports = validate(signedDoc, getDigestDocument());
		validateHashOnly(reports, true, false);
		reports = validateWrong(signedDoc);
		validateHashOnly(reports, false, false);

		DSSDocument extendDocument = service.extendDocument(signedDoc, getExtendParams());
		reports = validate(extendDocument, completeDocument);
		validateHashOnly(reports, false, false);
	}

	@Test
	public void testWithDigestDocument() {
		CAdESService service = getService();
		CAdESSignatureParameters params = getParams();
		DSSDocument digestDocument = getDigestDocument();

		ToBeSigned toBeSigned = service.getDataToSign(digestDocument, params);
		SignatureValue signatureValue = getToken().sign(toBeSigned, params.getDigestAlgorithm(), getPrivateKeyEntry());
		DSSDocument signedDoc = service.signDocument(digestDocument, params, signatureValue);

		Reports reports = validate(signedDoc, digestDocument);
		validateHashOnly(reports, true, false);
		reports = validate(signedDoc, getCompleteDocument());
		validateHashOnly(reports, false, false);
		reports = validateWrong(signedDoc);
		validateHashOnly(reports, false, false);

		DSSDocument extendDocument = service.extendDocument(signedDoc, getExtendParams());
		reports = validate(extendDocument, digestDocument);
		validateHashOnly(reports, true, false);
	}

	private Reports validate(DSSDocument signedDocument, DSSDocument original) {
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signedDocument);
		validator.setCertificateVerifier(getCompleteCertificateVerifier());
		validator.setDetachedContents(Arrays.asList(original));
		Reports reports = validator.validateDocument();

		DiagnosticData diagData = reports.getDiagnosticData();
		assertTrue(diagData.isBLevelTechnicallyValid(diagData.getFirstSignatureId()));
		return reports;
	}
	
	private void validateHashOnly(Reports reports, boolean expectedDocHashOnly, boolean expectedHashOnly) {
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertEquals(expectedDocHashOnly, signature.isDocHashOnly());
		assertEquals(expectedHashOnly, signature.isHashOnly());
		
		ValidationReportType etsiValidationReportJaxb = reports.getEtsiValidationReportJaxb();
		assertNotNull(etsiValidationReportJaxb);
		SignatureValidationReportType signatureValidationReport = etsiValidationReportJaxb.getSignatureValidationReport().get(0);
		assertNotNull(signatureValidationReport);
		SignatureIdentifierType signatureIdentifier = signatureValidationReport.getSignatureIdentifier();
		assertNotNull(signatureIdentifier);
		assertEquals(expectedDocHashOnly, signatureIdentifier.isDocHashOnly());
		assertEquals(expectedHashOnly, signatureIdentifier.isHashOnly());
	}

	private Reports validateWrong(DSSDocument signedDocument) {
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signedDocument);
		validator.setCertificateVerifier(getCompleteCertificateVerifier());
		validator.setDetachedContents(Arrays.asList(getWrongDocument()));
		Reports reports = validator.validateDocument();

		DiagnosticData diagData = reports.getDiagnosticData();
		assertFalse(diagData.isBLevelTechnicallyValid(diagData.getFirstSignatureId()));
		return reports;
	}

	private CAdESService getService() {
		CAdESService service = new CAdESService(getCompleteCertificateVerifier());
		service.setTspSource(getGoodTsa());
		return service;
	}

	private CAdESSignatureParameters getParams() {
		CAdESSignatureParameters signatureParameters = new CAdESSignatureParameters();
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setDigestAlgorithm(USED_DIGEST);
		signatureParameters.setSignaturePackaging(SignaturePackaging.DETACHED);
		signatureParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_B);
		return signatureParameters;
	}

	private CAdESSignatureParameters getExtendParams() {
		CAdESSignatureParameters signatureParameters = new CAdESSignatureParameters();
		signatureParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_T);
		signatureParameters.setDetachedContents(Arrays.asList(getDigestDocument()));
		return signatureParameters;
	}

	private DSSDocument getCompleteDocument() {
		return new InMemoryDocument("Hello World !".getBytes(), DOCUMENT_NAME);
	}

	private DSSDocument getDigestDocument() {
		DigestDocument digestDocument = new DigestDocument(USED_DIGEST, Utils.toBase64(DSSUtils.digest(USED_DIGEST, getCompleteDocument())));
		// digestDocument.setName(DOCUMENT_NAME);
		return digestDocument;
	}

	private DSSDocument getWrongDocument() {
		return new InMemoryDocument("Bye World !".getBytes(), DOCUMENT_NAME);
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

}
