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
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.IOException;
import java.util.Date;
import java.util.List;

import org.junit.Before;
import org.junit.Test;

import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.enumerations.CertificateSourceType;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.spi.x509.CommonCertificateSource;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.test.signature.PKIFactoryAccess;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;

public class XAdESLevelBWithMultipleTrustedCertificateSources extends PKIFactoryAccess {
			
	private DocumentSignatureService<XAdESSignatureParameters> service;
	private DSSDocument documentToSign;
	
	private XAdESSignatureParameters signatureParameters;
	private CertificateVerifier certificateVerifier;
	private Indication expectedResult;
	private boolean trustedStoreExpectedResult;
	
	@Before
	public void init() throws Exception {
		service = new XAdESService(getCompleteCertificateVerifier());
		
		signatureParameters = new XAdESSignatureParameters();
		signatureParameters.bLevel().setSigningDate(new Date());
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);

		documentToSign = new FileDocument(new File("src/test/resources/sample.xml"));
	}

	@Test
	public void validateWithValidTrustAnchorTest() throws IOException {
		DSSDocument signedDocument = sign();
		certificateVerifier = getCertificateVerifierWithoutTrustSources();
		CommonTrustedCertificateSource trusted = new CommonTrustedCertificateSource();
		trusted.importAsTrusted(getBelgiumTrustAnchors());
		certificateVerifier.setTrustedCertSource(trusted);
		expectedResult = Indication.TOTAL_PASSED;
		trustedStoreExpectedResult = true;
		validate(signedDocument);
	}
	
	@Test
	public void validateWithValidTrustAnchorAndAdjunctTest() throws IOException {
		DSSDocument signedDocument = sign();
		certificateVerifier = getCertificateVerifierWithoutTrustSources();
		CommonTrustedCertificateSource trusted = new CommonTrustedCertificateSource();
		trusted.importAsTrusted(getBelgiumTrustAnchors());
		certificateVerifier.setTrustedCertSource(trusted);
		
		CertificateSource cs = new CommonCertificateSource();
		cs.addCertificate(getCertificate(ROOT_CA));
		certificateVerifier.setAdjunctCertSource(cs);
		expectedResult = Indication.TOTAL_PASSED;
		trustedStoreExpectedResult = true;
		validate(signedDocument);
	}
	
	@Test
	public void validateWithInvalidTrustAnchorTest() throws IOException {
		DSSDocument signedDocument = sign();
		certificateVerifier = getCertificateVerifierWithoutTrustSources();
		CommonTrustedCertificateSource trusted = new CommonTrustedCertificateSource();
		trusted.importAsTrusted(getSHA3PKITrustAnchors());
		certificateVerifier.setTrustedCertSource(trusted);
		expectedResult = Indication.INDETERMINATE;
		trustedStoreExpectedResult = false;
		validate(signedDocument);
	}
	
	@Test
	public void validateWithBothTrustAnchorsTest() throws IOException {
		DSSDocument signedDocument = sign();
		certificateVerifier = getCertificateVerifierWithoutTrustSources();

		CommonTrustedCertificateSource trustedSource1 = new CommonTrustedCertificateSource();
		trustedSource1.importAsTrusted(getSHA3PKITrustAnchors());
		
		certificateVerifier.setTrustedCertSources(trustedSource1);
		expectedResult = Indication.INDETERMINATE;
		trustedStoreExpectedResult = false;
		validate(signedDocument);
		
		List<CertificateSource> trustedCertSources = certificateVerifier.getTrustedCertSources();
		assertEquals(1, trustedCertSources.size());

		CommonTrustedCertificateSource trustedSource2 = new CommonTrustedCertificateSource();
		trustedSource2.importAsTrusted(getBelgiumTrustAnchors());
		certificateVerifier.setTrustedCertSources(trustedSource2);
		
		trustedCertSources = certificateVerifier.getTrustedCertSources();
		assertEquals(2, trustedCertSources.size());
		
		expectedResult = Indication.TOTAL_PASSED;
		trustedStoreExpectedResult = true;
		validate(signedDocument);
	}

	@Test
	public void validateWithArrayOfTrustAnchorsTest() throws IOException {
		DSSDocument signedDocument = sign();
		certificateVerifier = getCertificateVerifierWithoutTrustSources();
		CommonTrustedCertificateSource trustedSource1 = new CommonTrustedCertificateSource();
		trustedSource1.importAsTrusted(getSHA3PKITrustAnchors());
		CommonTrustedCertificateSource trustedSource2 = new CommonTrustedCertificateSource();
		trustedSource2.importAsTrusted(getBelgiumTrustAnchors());
		certificateVerifier.setTrustedCertSources(trustedSource1, trustedSource2);
		expectedResult = Indication.TOTAL_PASSED;
		trustedStoreExpectedResult = true;
		validate(signedDocument);
	}
	
	@Test
	public void validateWithArrayOfDuplicateTrustAnchorsTest() throws IOException {
		DSSDocument signedDocument = sign();
		certificateVerifier = getCertificateVerifierWithoutTrustSources();
		CommonTrustedCertificateSource trustedSource1 = new CommonTrustedCertificateSource();
		trustedSource1.importAsTrusted(getBelgiumTrustAnchors());
		certificateVerifier.setTrustedCertSources(trustedSource1, trustedSource1);
		expectedResult = Indication.TOTAL_PASSED;
		trustedStoreExpectedResult = true;
		validate(signedDocument);
	}

	private DSSDocument sign() throws IOException {
		ToBeSigned dataToSign = service.getDataToSign(documentToSign, signatureParameters);
		SignatureValue signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
		return service.signDocument(documentToSign, signatureParameters, signatureValue);
	}
	
	private void validate(DSSDocument signedDocument) {
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signedDocument);
		validator.setCertificateVerifier(certificateVerifier);
		Reports reports = validator.validateDocument();
		
		// reports.print();

		DiagnosticData diagnosticData = reports.getDiagnosticData();
		assertTrue(diagnosticData.isBLevelTechnicallyValid(diagnosticData.getFirstSignatureId()));
		
		verifyDiagnosticData(diagnosticData);
				
		SimpleReport simpleReport = reports.getSimpleReport();
		verifySimpleReport(simpleReport);
	}

	private void verifyDiagnosticData(DiagnosticData diagnosticData) {
		boolean result = false;
		for (CertificateWrapper certificate : diagnosticData.getUsedCertificates()) {
			List<CertificateSourceType> sources = certificate.getSources();
			for(CertificateSourceType type: sources) {
				if(type == CertificateSourceType.TRUSTED_STORE)
					result = true;
			}
		}
		
		assertEquals(trustedStoreExpectedResult, result);
	}
	
	private void verifySimpleReport(SimpleReport simpleReport) {
		assertNotNull(simpleReport);

		List<String> signatureIdList = simpleReport.getSignatureIdList();
		assertTrue(Utils.isCollectionNotEmpty(signatureIdList));

		for (String sigId : signatureIdList) {
			Indication indication = simpleReport.getIndication(sigId);
			assertNotNull(indication);
			if (indication != Indication.TOTAL_PASSED) {
				assertNotNull(simpleReport.getSubIndication(sigId));
			}
			assertNotNull(simpleReport.getSignatureQualification(sigId));
						
			assertEquals(expectedResult, simpleReport.getIndication(sigId));
		}
		assertNotNull(simpleReport.getValidationTime());
	}
	
	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

}
