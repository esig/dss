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

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Date;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.Policy;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.test.PKIFactoryAccess;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;

public class CAdESLevelBWithZeroPolicyTest extends PKIFactoryAccess {

	private static final String POLICY_ID = "1.2.3.4.5.6";
	private static final String HELLO_WORLD = "Hello World";
	private static final String HTTP_SPURI_TEST = "";

	private DocumentSignatureService<CAdESSignatureParameters, CAdESTimestampParameters> service;
	private CAdESSignatureParameters signatureParameters;
	private DSSDocument documentToSign;
	private DSSDocument signedDocument;
	private Policy signaturePolicy;

	@BeforeEach
	public void init(){
		documentToSign = new InMemoryDocument(HELLO_WORLD.getBytes());
		
		signaturePolicy = new Policy();
		signaturePolicy.setId(POLICY_ID);
		signaturePolicy.setDigestAlgorithm(DigestAlgorithm.SHA1);
		signaturePolicy.setSpuri(HTTP_SPURI_TEST);
		
		signatureParameters = new CAdESSignatureParameters();
		signatureParameters.bLevel().setSigningDate(new Date());
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
		signatureParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_B);

		service = new CAdESService(getOfflineCertificateVerifier());
	}
	
	@Test
	public void zeroPolicyWithZeroTest() throws Exception {
		signaturePolicy.setDigestValue("0".getBytes());		
		signatureParameters.bLevel().setSignaturePolicy(signaturePolicy);
		signer();
		testSignatureTrueZeroPolicy();
	}
	
	@Test
	public void zeroPolicyWithEmptyFieldTest() throws Exception {
		signaturePolicy.setDigestValue("".getBytes());		
		signatureParameters.bLevel().setSignaturePolicy(signaturePolicy);
		signer();
		testSignatureTrueZeroPolicy();
	}
	
	@Test
	public void zeroPolicyWithByteZeroTest() throws Exception {
		signaturePolicy.setDigestValue(new byte[]{0x00});		
		signatureParameters.bLevel().setSignaturePolicy(signaturePolicy);
		signer();
		testSignatureTrueZeroPolicy();
	}
	
	@Test
	public void zeroPolicyWithOtherValuesTest() throws Exception {
		signaturePolicy.setDigestValue("00".getBytes());		
		signatureParameters.bLevel().setSignaturePolicy(signaturePolicy);
		signer();
		testSignatureFalseZeroPolicy();
	}
	
	@Test
	public void zeroPolicyWithHashedZeroTest() throws Exception {
	    byte[] digest = DSSUtils.digest(DigestAlgorithm.SHA1, new byte[] {'0'});
		signaturePolicy.setDigestValue(digest);		
		signatureParameters.bLevel().setSignaturePolicy(signaturePolicy);
		signer();
		testSignatureFalseZeroPolicy();
	}
	
	@Test
	public void zeroPolicyWithHashedArrayOfZerosTest() throws Exception {
		signaturePolicy.setDigestValue(new byte[] {
				'0', '0', '0', '0', '0', '0', '0', '0', '0', '0', 
				'0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
				'0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
				'0', '0', '0', '0', '0', '0', '0', '0', '0', '0'
		});		
		signatureParameters.bLevel().setSignaturePolicy(signaturePolicy);
		signer();
		testSignatureFalseZeroPolicy();
	}
	
	public void signer() {
		ToBeSigned dataToSign = service.getDataToSign(documentToSign, signatureParameters);
		SignatureValue signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
		assertTrue(service.isValidSignatureValue(dataToSign, signatureValue, getSigningCert()));
		signedDocument = service.signDocument(documentToSign, signatureParameters, signatureValue);
	}
	
	public void testSignatureTrueZeroPolicy() {
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signedDocument);
		validator.setCertificateVerifier(new CommonCertificateVerifier());
		
		Reports reports = validator.validateDocument();
		assertNotNull(reports);
//		reports.print();
		
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());		
		CertificateWrapper signingCertificate = signature.getSigningCertificate();
		assertNotNull(signingCertificate);
		assertTrue(signature.isPolicyPresent());
		assertTrue(signature.isPolicyZeroHash());
	}
	
	public void testSignatureFalseZeroPolicy() {
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signedDocument);
		validator.setCertificateVerifier(new CommonCertificateVerifier());
		
		Reports reports = validator.validateDocument();
		assertNotNull(reports);
//		reports.print();
		
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());		
		CertificateWrapper signingCertificate = signature.getSigningCertificate();
		assertNotNull(signingCertificate);
		assertTrue(signature.isPolicyPresent());
		assertFalse(signature.isPolicyZeroHash());
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}
}
