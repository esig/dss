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
package eu.europa.esig.dss.xades.signature;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.Pkcs12SignatureToken;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.IOException;
import java.security.KeyStore.PasswordProtection;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class CertificateConflictTest {

	private final PasswordProtection passwordProtection = new PasswordProtection("1qaz@WSX".toCharArray());

	@Test
	void testXadesCaDuplicate() throws IOException {
		DSSDocument signedDocument = xadesSign(new FileDocument("src/test/resources/sample.xml"));
		assertEquals(MimeTypeEnum.XML, signedDocument.getMimeType());
		xadesVerifyPreviousKeystore(signedDocument);
		xadesVerifyCurrentKeystore(signedDocument);
	}

	private DSSDocument xadesSign(DSSDocument document) throws IOException {
		File ksFile = new File("src/test/resources/cert-conflict/previousKeystore.pfx");
		Pkcs12SignatureToken signatureToken = new Pkcs12SignatureToken(ksFile, passwordProtection);
		DSSPrivateKeyEntry privateKey = signatureToken.getKeys().get(0);

		XAdESSignatureParameters parameters = new XAdESSignatureParameters();
		parameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
		parameters.setSignaturePackaging(SignaturePackaging.ENVELOPED);
		parameters.setDigestAlgorithm(DigestAlgorithm.SHA256);

		parameters.setSigningCertificate(privateKey.getCertificate());
		parameters.setCertificateChain(privateKey.getCertificateChain());

		CommonCertificateVerifier verifier = new CommonCertificateVerifier();
		XAdESService xadesService = new XAdESService(verifier);
		ToBeSigned dataToSign = xadesService.getDataToSign(document, parameters);

		DigestAlgorithm digestAlgorithm = parameters.getDigestAlgorithm();
		SignatureValue signatureValue = signatureToken.sign(dataToSign, digestAlgorithm, privateKey);
		return xadesService.signDocument(document, parameters, signatureValue);
	}

	private void xadesVerifyPreviousKeystore(DSSDocument signedDocument) throws IOException {
		File ksFile = new File("src/test/resources/cert-conflict/previousKeystore.pfx");
		Pkcs12SignatureToken signatureToken = new Pkcs12SignatureToken(ksFile, passwordProtection);
		DSSPrivateKeyEntry privateKey = signatureToken.getKeys().get(0);

		CertificateVerifier cv = new CommonCertificateVerifier();

		CommonTrustedCertificateSource certificateSource = new CommonTrustedCertificateSource();
		for (CertificateToken cert : privateKey.getCertificateChain()) {
			certificateSource.addCertificate(cert);
		}
		cv.setTrustedCertSources(certificateSource);

		SignedDocumentValidator documentValidator = SignedDocumentValidator.fromDocument(signedDocument);
		documentValidator.setCertificateVerifier(cv);
		Reports reports = documentValidator.validateDocument();
		assertNotNull(reports);
		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(1, simpleReport.getSignatureIdList().size());
		String signatureId = simpleReport.getSignatureIdList().get(0);
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(signatureId));
	}

	private void xadesVerifyCurrentKeystore(DSSDocument signedDocument) throws IOException {
		File ksFile = new File("src/test/resources/cert-conflict/currentKeystore.pfx");
		Pkcs12SignatureToken signatureToken = new Pkcs12SignatureToken(ksFile, passwordProtection);
		DSSPrivateKeyEntry privateKey = signatureToken.getKeys().get(0);

		CertificateVerifier cv = new CommonCertificateVerifier();

		CommonTrustedCertificateSource certificateSource = new CommonTrustedCertificateSource();
		for (CertificateToken cert : privateKey.getCertificateChain()) {
			certificateSource.addCertificate(cert);
		}
		cv.setTrustedCertSources(certificateSource);

		SignedDocumentValidator documentValidator = SignedDocumentValidator.fromDocument(signedDocument);
		documentValidator.setCertificateVerifier(cv);
		Reports reports = documentValidator.validateDocument();
		assertNotNull(reports);
		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(1, simpleReport.getSignatureIdList().size());
		String signatureId = simpleReport.getSignatureIdList().get(0);
		assertNotEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(signatureId));
		assertNotEquals(Indication.PASSED, simpleReport.getIndication(signatureId));
	}

}
