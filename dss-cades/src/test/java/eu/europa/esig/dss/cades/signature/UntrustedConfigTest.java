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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.alert.LogOnStatusAlert;
import eu.europa.esig.dss.alert.exception.AlertException;
import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.test.PKIFactoryAccess;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;

public class UntrustedConfigTest extends PKIFactoryAccess {

	private DSSDocument documentToSign = new InMemoryDocument("Hello World !".getBytes(), "test.text");

	@Test
	public void untrustedCert() {
		CAdESSignatureParameters params = new CAdESSignatureParameters();
		params.setSigningCertificate(getSigningCert());
		params.setCertificateChain(getCertificateChain());
		params.setSignatureLevel(SignatureLevel.CAdES_BASELINE_B);
		params.setSignaturePackaging(SignaturePackaging.ENVELOPING);

		CAdESService service = new CAdESService(getOfflineCertificateVerifier());
		ToBeSigned dataToSign = service.getDataToSign(documentToSign, params);
		SignatureValue signatureValue = getToken().sign(dataToSign, params.getDigestAlgorithm(), getPrivateKeyEntry());
		DSSDocument signedDocument = service.signDocument(documentToSign, params, signatureValue);
		assertNotNull(signedDocument);

		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signedDocument);
		validator.setCertificateVerifier(getOfflineCertificateVerifier());
		Reports reports = validator.validateDocument();

		DiagnosticData diagnosticData = reports.getDiagnosticData();
		assertTrue(diagnosticData.isBLevelTechnicallyValid(diagnosticData.getFirstSignatureId()));
	}

	@Test
	public void untrustedCertLT() {
		CAdESSignatureParameters params = new CAdESSignatureParameters();
		params.setSigningCertificate(getSigningCert());
		params.setCertificateChain(getCertificateChain());
		params.setSignatureLevel(SignatureLevel.CAdES_BASELINE_LT);
		params.setSignaturePackaging(SignaturePackaging.ENVELOPING);

		CertificateVerifier certificateVerifier = getCompleteCertificateVerifier();
		// Default
		// certificateVerifier.setCheckRevocationForUntrustedChains(false);
		// certificateVerifier.setExceptionOnMissingRevocationData(true);
		CAdESService service = new CAdESService(certificateVerifier);
		service.setTspSource(getGoodTsa());

		ToBeSigned dataToSign = service.getDataToSign(documentToSign, params);
		SignatureValue signatureValue = getToken().sign(dataToSign, params.getDigestAlgorithm(), getPrivateKeyEntry());
		assertThrows(AlertException.class, () -> service.signDocument(documentToSign, params, signatureValue));
	}

	@Test
	public void untrustedCertLT2() {
		CAdESSignatureParameters params = new CAdESSignatureParameters();
		params.setSigningCertificate(getSigningCert());
		params.setCertificateChain(getCertificateChain());
		params.setSignatureLevel(SignatureLevel.CAdES_BASELINE_LT);
		params.setSignaturePackaging(SignaturePackaging.ENVELOPING);

		CertificateVerifier certificateVerifier = getOfflineCertificateVerifier();
		certificateVerifier.setCheckRevocationForUntrustedChains(true);
		// certificateVerifier.setExceptionOnMissingRevocationData(true);

		CAdESService service = new CAdESService(certificateVerifier);
		service.setTspSource(getGoodTsa());

		ToBeSigned dataToSign = service.getDataToSign(documentToSign, params);
		SignatureValue signatureValue = getToken().sign(dataToSign, params.getDigestAlgorithm(), getPrivateKeyEntry());
		assertThrows(AlertException.class, () -> service.signDocument(documentToSign, params, signatureValue));
	}

	@Test
	public void untrustedCertLTNotRecommendedConfig() {
		CAdESSignatureParameters params = new CAdESSignatureParameters();
		params.setSigningCertificate(getSigningCert());
		params.setCertificateChain(getCertificateChain());
		params.setSignatureLevel(SignatureLevel.CAdES_BASELINE_LT);
		params.setSignaturePackaging(SignaturePackaging.ENVELOPING);

		CertificateVerifier certificateVerifier = getOfflineCertificateVerifier();
		certificateVerifier.setCheckRevocationForUntrustedChains(true);
		certificateVerifier.setAlertOnMissingRevocationData(new LogOnStatusAlert());

		CAdESService service = new CAdESService(certificateVerifier);
		service.setTspSource(getGoodTsa());

		ToBeSigned dataToSign = service.getDataToSign(documentToSign, params);
		SignatureValue signatureValue = getToken().sign(dataToSign, params.getDigestAlgorithm(), getPrivateKeyEntry());
		DSSDocument signedDocument = service.signDocument(documentToSign, params, signatureValue);
		assertNotNull(signedDocument);

		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signedDocument);
		validator.setCertificateVerifier(getOfflineCertificateVerifier());
		Reports reports = validator.validateDocument();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(SignatureLevel.CAdES_BASELINE_T, simpleReport.getSignatureFormat(simpleReport.getFirstSignatureId()));
	}

	@Test
	public void untrustedCertLTForce() {
		CAdESSignatureParameters params = new CAdESSignatureParameters();
		params.setSigningCertificate(getSigningCert());
		params.setCertificateChain(getCertificateChain());
		params.setSignatureLevel(SignatureLevel.CAdES_BASELINE_LT);
		params.setSignaturePackaging(SignaturePackaging.ENVELOPING);

		CertificateVerifier certificateVerifier = getCompleteCertificateVerifier();
		// Will request OCSP/CRL
		certificateVerifier.setCheckRevocationForUntrustedChains(true);
		CAdESService service = new CAdESService(certificateVerifier);
		service.setTspSource(getGoodTsa());

		ToBeSigned dataToSign = service.getDataToSign(documentToSign, params);
		SignatureValue signatureValue = getToken().sign(dataToSign, params.getDigestAlgorithm(), getPrivateKeyEntry());
		DSSDocument signedDocument = service.signDocument(documentToSign, params, signatureValue);
		assertNotNull(signedDocument);

		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signedDocument);
		validator.setCertificateVerifier(getOfflineCertificateVerifier());
		Reports reports = validator.validateDocument();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(SignatureLevel.CAdES_BASELINE_LT, simpleReport.getSignatureFormat(simpleReport.getFirstSignatureId()));
	}

	@Override
	protected String getSigningAlias() {
		return UNTRUSTED_USER;
	}

}
