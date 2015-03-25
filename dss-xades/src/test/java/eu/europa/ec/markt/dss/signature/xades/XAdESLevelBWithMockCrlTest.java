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
package eu.europa.ec.markt.dss.signature.xades;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;

import java.io.File;
import java.security.cert.X509CRL;
import java.util.Date;

import org.bouncycastle.asn1.x509.CRLReason;
import org.junit.Before;

import eu.europa.ec.markt.dss.SignatureAlgorithm;
import eu.europa.ec.markt.dss.mock.MockCRLSource;
import eu.europa.ec.markt.dss.parameter.AbstractSignatureParameters;
import eu.europa.ec.markt.dss.parameter.XAdESSignatureParameters;
import eu.europa.ec.markt.dss.service.CRLGenerator;
import eu.europa.ec.markt.dss.service.CertificateService;
import eu.europa.ec.markt.dss.signature.AbstractTestSignature;
import eu.europa.ec.markt.dss.signature.DSSDocument;
import eu.europa.ec.markt.dss.signature.DocumentSignatureService;
import eu.europa.ec.markt.dss.signature.FileDocument;
import eu.europa.ec.markt.dss.signature.MimeType;
import eu.europa.ec.markt.dss.signature.SignatureLevel;
import eu.europa.ec.markt.dss.signature.SignaturePackaging;
import eu.europa.ec.markt.dss.signature.token.DSSPrivateKeyEntry;
import eu.europa.ec.markt.dss.validation102853.CertificateVerifier;
import eu.europa.ec.markt.dss.validation102853.CommonCertificateVerifier;
import eu.europa.ec.markt.dss.validation102853.SignedDocumentValidator;
import eu.europa.ec.markt.dss.validation102853.crl.CRLReasonEnum;
import eu.europa.ec.markt.dss.validation102853.report.DiagnosticData;
import eu.europa.ec.markt.dss.validation102853.report.Reports;

public class XAdESLevelBWithMockCrlTest extends AbstractTestSignature {

	private DocumentSignatureService<XAdESSignatureParameters> service;
	private XAdESSignatureParameters signatureParameters;
	private DSSDocument documentToSign;
	private DSSPrivateKeyEntry issuerEntry;
	private DSSPrivateKeyEntry signerEntry;

	private X509CRL generatedCRL;

	@Before
	public void init() throws Exception {
		documentToSign = new FileDocument(new File("src/test/resources/sample.xml"));

		CertificateService certificateService = new CertificateService();
		issuerEntry = certificateService.generateSelfSignedCertificate(SignatureAlgorithm.RSA_SHA256);
		signerEntry = certificateService.generateCertificateChain(SignatureAlgorithm.RSA_SHA1, issuerEntry);

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
	protected DSSPrivateKeyEntry getPrivateKeyEntry() {
		return signerEntry;
	}

}
