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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;

import java.io.File;
import java.security.cert.X509CRL;
import java.util.Date;

import org.bouncycastle.asn1.x509.CRLReason;
import org.junit.Before;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.MimeType;
import eu.europa.esig.dss.SignatureAlgorithm;
import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.signature.AbstractTestSignature;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.signature.SignaturePackaging;
import eu.europa.esig.dss.test.gen.CRLGenerator;
import eu.europa.esig.dss.test.gen.CertificateService;
import eu.europa.esig.dss.test.mock.MockCRLSource;
import eu.europa.esig.dss.test.mock.MockPrivateKeyEntry;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.report.DiagnosticData;
import eu.europa.esig.dss.validation.report.Reports;
import eu.europa.esig.dss.x509.crl.CRLReasonEnum;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;

public class XAdESLevelBWithMockCrlTest extends AbstractTestSignature {

	private DocumentSignatureService<XAdESSignatureParameters> service;
	private XAdESSignatureParameters signatureParameters;
	private DSSDocument documentToSign;
	private MockPrivateKeyEntry issuerEntry;
	private MockPrivateKeyEntry signerEntry;

	private X509CRL generatedCRL;

	@Before
	public void init() throws Exception {
		documentToSign = new FileDocument(new File("src/test/resources/sample.xml"));

		CertificateService certificateService = new CertificateService();
		issuerEntry = certificateService.generateSelfSignedCertificate(SignatureAlgorithm.RSA_SHA256);
		signerEntry = certificateService.generateCertificateChain(SignatureAlgorithm.RSA_SHA256, issuerEntry);

		CRLGenerator crlGenerator = new CRLGenerator();
		generatedCRL = crlGenerator.generateCRL(signerEntry.getCertificate().getCertificate(), issuerEntry, new Date(), CRLReason.privilegeWithdrawn);

		signatureParameters = new XAdESSignatureParameters();
		signatureParameters.bLevel().setSigningDate(new Date());
		signatureParameters.setSigningCertificate(signerEntry.getCertificate());
		signatureParameters.setCertificateChain(signerEntry.getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);

		CertificateVerifier certificateVerifier = new CommonCertificateVerifier();
		service = new XAdESService(certificateVerifier);

	}

	@Override
	protected Reports getValidationReport(final DSSDocument signedDocument) {
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signedDocument);
		CommonCertificateVerifier certificateVerifier = new CommonCertificateVerifier();
		certificateVerifier.setCrlSource(new MockCRLSource(generatedCRL));
		validator.setCertificateVerifier(certificateVerifier);
		Reports reports = validator.validateDocument();
		return reports;
	}

	@Override
	protected void verifyDiagnosticData(DiagnosticData diagnosticData) {
		super.verifyDiagnosticData(diagnosticData);

		// TODO improve if not revocation info found, that returns false (add a
		// method hasRevocationInfo)
		String signingCertificateId = diagnosticData.getSigningCertificateId();
		assertFalse(diagnosticData.getCertificateRevocationStatus(signingCertificateId));
		assertEquals(CRLReasonEnum.privilegeWithdrawn.name(), diagnosticData.getCertificateRevocationReason(signingCertificateId));
		assertEquals("CRLToken", diagnosticData.getCertificateRevocationSource(signingCertificateId));
	}

	@Override
	protected DocumentSignatureService<XAdESSignatureParameters> getService() {
		return service;
	}

	@Override
	protected XAdESSignatureParameters getSignatureParameters() {
		return signatureParameters;
	}

	@Override
	protected MimeType getExpectedMime() {
		return MimeType.XML;
	}

	@Override
	protected boolean isBaselineT() {
		return false;
	}

	@Override
	protected boolean isBaselineLTA() {
		return false;
	}

	@Override
	protected DSSDocument getDocumentToSign() {
		return documentToSign;
	}

	@Override
	protected MockPrivateKeyEntry getPrivateKeyEntry() {
		return signerEntry;
	}

}
