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
package eu.europa.ec.markt.dss.signature.cades;

import static org.junit.Assert.assertEquals;

import java.util.Date;

import org.junit.Before;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.ec.markt.dss.DigestAlgorithm;
import eu.europa.ec.markt.dss.SignatureAlgorithm;
import eu.europa.ec.markt.dss.parameter.CAdESSignatureParameters;
import eu.europa.ec.markt.dss.parameter.Policy;
import eu.europa.ec.markt.dss.service.CertificateService;
import eu.europa.ec.markt.dss.signature.AbstractTestSignature;
import eu.europa.ec.markt.dss.signature.DSSDocument;
import eu.europa.ec.markt.dss.signature.DocumentSignatureService;
import eu.europa.ec.markt.dss.signature.InMemoryDocument;
import eu.europa.ec.markt.dss.signature.MimeType;
import eu.europa.ec.markt.dss.signature.SignatureLevel;
import eu.europa.ec.markt.dss.signature.SignaturePackaging;
import eu.europa.ec.markt.dss.signature.token.DSSPrivateKeyEntry;
import eu.europa.ec.markt.dss.validation102853.CertificateVerifier;
import eu.europa.ec.markt.dss.validation102853.CommonCertificateVerifier;
import eu.europa.ec.markt.dss.validation102853.report.DiagnosticData;

public class CAdESLevelBWithPolicyTest extends AbstractTestSignature {

	private static final String POLICY_ID = "1.2.3.4.5.6";
	private static final String HELLO_WORLD = "Hello World";
	private static final String HTTP_SPURI_TEST = "http://spuri.test";

	private static Logger logger = LoggerFactory.getLogger(CAdESLevelBWithPolicyTest.class);

	private DocumentSignatureService<CAdESSignatureParameters> service;
	private CAdESSignatureParameters signatureParameters;
	private DSSDocument documentToSign;
	private DSSPrivateKeyEntry privateKeyEntry;

	@Before
	public void init() throws Exception {
		documentToSign = new InMemoryDocument(HELLO_WORLD.getBytes());

		CertificateService certificateService = new CertificateService();
		privateKeyEntry = certificateService.generateCertificateChain(SignatureAlgorithm.RSA_SHA256);

		Policy signaturePolicy = new Policy();
		signaturePolicy.setId(POLICY_ID);
		signaturePolicy.setDigestAlgorithm(DigestAlgorithm.SHA1);
		signaturePolicy.setDigestValue(new byte[] {
				'd', 'i', 'g', 'e', 's', 't', 'v', 'a', 'l', 'u', 'e'
		});
		signaturePolicy.setSpuri(HTTP_SPURI_TEST);

		signatureParameters = new CAdESSignatureParameters();
		signatureParameters.bLevel().setSigningDate(new Date());
		signatureParameters.bLevel().setSignaturePolicy(signaturePolicy);
		signatureParameters.setSigningCertificate(privateKeyEntry.getCertificate());
		signatureParameters.setCertificateChain(privateKeyEntry.getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
		signatureParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_B);

		CertificateVerifier certificateVerifier = new CommonCertificateVerifier();
		service = new CAdESService(certificateVerifier);

	}


	@Override
	protected void verifyDiagnosticData(DiagnosticData diagnosticData) {
		super.verifyDiagnosticData(diagnosticData);
		String policyId = diagnosticData.getPolicyId();
		assertEquals(POLICY_ID, policyId);
	}

	@Override
	protected DocumentSignatureService<CAdESSignatureParameters> getService() {
		return service;
	}

	@Override
	protected CAdESSignatureParameters getSignatureParameters() {
		return signatureParameters;
	}

	@Override
	protected MimeType getExpectedMime() {
		return MimeType.PKCS7;
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
		return privateKeyEntry;
	}

}
