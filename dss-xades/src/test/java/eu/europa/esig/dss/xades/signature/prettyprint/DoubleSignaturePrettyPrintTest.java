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
package eu.europa.esig.dss.xades.signature.prettyprint;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.RelatedCertificateWrapper;
import eu.europa.esig.dss.diagnostic.RevocationRefWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.CertificateOrigin;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.test.PKIFactoryAccess;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.xades.DSSXMLUtils;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.signature.XAdESService;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DoubleSignaturePrettyPrintTest extends PKIFactoryAccess {

	@Test
	void firstOnlySignaturesPrettyPrintTest() {

		DSSDocument toBeSigned = new FileDocument(new File("src/test/resources/sample.xml"));

		XAdESService service = new XAdESService(getOfflineCertificateVerifier());

		XAdESSignatureParameters params = new XAdESSignatureParameters();
		params.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
		params.setSignaturePackaging(SignaturePackaging.ENVELOPED);
		params.setSigningCertificate(getSigningCert());
		params.setPrettyPrint(true);

		ToBeSigned dataToSign = service.getDataToSign(toBeSigned, params);
		SignatureValue signatureValue = getToken().sign(dataToSign, params.getDigestAlgorithm(), getPrivateKeyEntry());
		DSSDocument signedDocument = service.signDocument(toBeSigned, params, signatureValue);
		// signedDocument.save("target/" + "doubleSignedTestFirst.xml");
		
		validate(signedDocument);

		params = new XAdESSignatureParameters();
		params.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
		params.setSignaturePackaging(SignaturePackaging.ENVELOPED);
		params.setSigningCertificate(getSigningCert());
		params.setPrettyPrint(false);

		dataToSign = service.getDataToSign(signedDocument, params);
		signatureValue = getToken().sign(dataToSign, params.getDigestAlgorithm(), getPrivateKeyEntry());
		DSSDocument doubleSignedDocument = service.signDocument(signedDocument, params, signatureValue);
		// doubleSignedDocument.save("target/" + "doubleSignedTestSecond.xml");

		validate(doubleSignedDocument);

		assertFalse(DSSXMLUtils.isDuplicateIdsDetected(doubleSignedDocument));
	}

	@Test
	void secondSignaturePrettyPrintTest() {

		DSSDocument toBeSigned = new FileDocument(new File("src/test/resources/sample.xml"));

		XAdESService service = new XAdESService(getOfflineCertificateVerifier());

		XAdESSignatureParameters params = new XAdESSignatureParameters();
		params.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
		params.setSignaturePackaging(SignaturePackaging.ENVELOPED);
		params.setSigningCertificate(getSigningCert());

		ToBeSigned dataToSign = service.getDataToSign(toBeSigned, params);
		SignatureValue signatureValue = getToken().sign(dataToSign, params.getDigestAlgorithm(), getPrivateKeyEntry());
		DSSDocument signedDocument = service.signDocument(toBeSigned, params, signatureValue);
		// signedDocument.save("target/" + "doubleSignedTestFirst.xml");
		
		validate(signedDocument);

		params = new XAdESSignatureParameters();
		params.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
		params.setSignaturePackaging(SignaturePackaging.ENVELOPED);
		params.setSigningCertificate(getSigningCert());
		params.setPrettyPrint(true);

		dataToSign = service.getDataToSign(signedDocument, params);
		signatureValue = getToken().sign(dataToSign, params.getDigestAlgorithm(), getPrivateKeyEntry());
		DSSDocument doubleSignedDocument = service.signDocument(signedDocument, params, signatureValue);
		// doubleSignedDocument.save("target/" + "doubleSignedTestSecond.xml");

		validate(doubleSignedDocument);

		assertFalse(DSSXMLUtils.isDuplicateIdsDetected(doubleSignedDocument));
	}

	@Test
	void bothSignaturesPrettyPrintTest() {

		DSSDocument toBeSigned = new FileDocument(new File("src/test/resources/sample.xml"));

		XAdESService service = new XAdESService(getOfflineCertificateVerifier());

		XAdESSignatureParameters params = new XAdESSignatureParameters();
		params.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
		params.setSignaturePackaging(SignaturePackaging.ENVELOPED);
		params.setSigningCertificate(getSigningCert());
		params.setPrettyPrint(true);

		ToBeSigned dataToSign = service.getDataToSign(toBeSigned, params);
		SignatureValue signatureValue = getToken().sign(dataToSign, params.getDigestAlgorithm(), getPrivateKeyEntry());
		DSSDocument signedDocument = service.signDocument(toBeSigned, params, signatureValue);
		// signedDocument.save("target/" + "doubleSignedTestFirst.xml");
		
		validate(signedDocument);

		params = new XAdESSignatureParameters();
		params.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
		params.setSignaturePackaging(SignaturePackaging.ENVELOPED);
		params.setSigningCertificate(getSigningCert());
		params.setPrettyPrint(true);

		dataToSign = service.getDataToSign(signedDocument, params);
		signatureValue = getToken().sign(dataToSign, params.getDigestAlgorithm(), getPrivateKeyEntry());
		DSSDocument doubleSignedDocument = service.signDocument(signedDocument, params, signatureValue);
		// doubleSignedDocument.save("target/" + "doubleSignedTestSecond.xml");

		validate(doubleSignedDocument);

		assertFalse(DSSXMLUtils.isDuplicateIdsDetected(doubleSignedDocument));
	}
	
	@Test
	void doubleSignatureLTALevelTest() {

		DSSDocument toBeSigned = new FileDocument(new File("src/test/resources/sample.xml"));

		XAdESService service = new XAdESService(getCompleteCertificateVerifier());
		service.setTspSource(getGoodTsa());

		XAdESSignatureParameters params = new XAdESSignatureParameters();
		params.setSignatureLevel(SignatureLevel.XAdES_BASELINE_LTA);
		params.setSignaturePackaging(SignaturePackaging.ENVELOPED);
		params.setSigningCertificate(getSigningCert());
		params.setPrettyPrint(true);

		ToBeSigned dataToSign = service.getDataToSign(toBeSigned, params);
		SignatureValue signatureValue = getToken().sign(dataToSign, params.getDigestAlgorithm(), getPrivateKeyEntry());
		DSSDocument signedDocument = service.signDocument(toBeSigned, params, signatureValue);
		// signedDocument.save("target/" + "doubleSignedTestFirst.xml");
		
		validate(signedDocument);

		params = new XAdESSignatureParameters();
		params.setSignatureLevel(SignatureLevel.XAdES_BASELINE_LTA);
		params.setSignaturePackaging(SignaturePackaging.ENVELOPED);
		params.setSigningCertificate(getSigningCert());
		params.setPrettyPrint(true);

		dataToSign = service.getDataToSign(signedDocument, params);
		signatureValue = getToken().sign(dataToSign, params.getDigestAlgorithm(), getPrivateKeyEntry());
		DSSDocument doubleSignedDocument = service.signDocument(signedDocument, params, signatureValue);
		// doubleSignedDocument.save("target/" + "doubleSignedTestSecond.xml");

		validate(doubleSignedDocument);

		assertFalse(DSSXMLUtils.isDuplicateIdsDetected(doubleSignedDocument));
		
	}
	
	@Test
	void doubleSignatureMixedLevelTest() {

		DSSDocument toBeSigned = new FileDocument(new File("src/test/resources/sample.xml"));

		XAdESService service = new XAdESService(getCompleteCertificateVerifier());
		service.setTspSource(getGoodTsa());

		XAdESSignatureParameters params = new XAdESSignatureParameters();
		params.setSignatureLevel(SignatureLevel.XAdES_BASELINE_LTA);
		params.setSignaturePackaging(SignaturePackaging.ENVELOPED);
		params.setSigningCertificate(getSigningCert());
		params.setPrettyPrint(false);

		ToBeSigned dataToSign = service.getDataToSign(toBeSigned, params);
		SignatureValue signatureValue = getToken().sign(dataToSign, params.getDigestAlgorithm(), getPrivateKeyEntry());
		DSSDocument signedDocument = service.signDocument(toBeSigned, params, signatureValue);
		// signedDocument.save("target/" + "doubleSignedTestFirst.xml");
		
		validate(signedDocument);

		params = new XAdESSignatureParameters();
		params.setSignatureLevel(SignatureLevel.XAdES_A);
		params.setSignaturePackaging(SignaturePackaging.ENVELOPED);
		params.setSigningCertificate(getSigningCert());
		params.setEn319132(false);
		params.setPrettyPrint(true);

		dataToSign = service.getDataToSign(signedDocument, params);
		signatureValue = getToken().sign(dataToSign, params.getDigestAlgorithm(), getPrivateKeyEntry());
		DSSDocument doubleSignedDocument = service.signDocument(signedDocument, params, signatureValue);
		// doubleSignedDocument.save("target/" + "doubleSignedTestSecond.xml");

		validate(doubleSignedDocument);

		assertFalse(DSSXMLUtils.isDuplicateIdsDetected(doubleSignedDocument));
		
	}
	
	@Test
	void doubleCreatedSignatureTest() {
		DiagnosticData diagnosticData = validate(new FileDocument("src/test/resources/validation/doubleSignedTest.xml"));
		List<SignatureWrapper> signatures = diagnosticData.getSignatures();
		assertEquals(2, signatures.size());
		SignatureWrapper signatureWrapper = signatures.get(0);
		List<RevocationRefWrapper> allFoundRevocationRefs = signatureWrapper.foundRevocations().getRelatedRevocationRefs();
		assertNotNull(allFoundRevocationRefs);
		assertEquals(0, allFoundRevocationRefs.size());
		
		assertEquals(2, signatureWrapper.foundRevocations().getRelatedRevocationData().size());
		assertEquals(0, signatureWrapper.foundRevocations().getOrphanRevocationData().size());
		
		List<RelatedCertificateWrapper> foundCertificatesByLocation = signatureWrapper.foundCertificates()
				.getRelatedCertificatesByOrigin(CertificateOrigin.CERTIFICATE_VALUES);
		assertNotNull(foundCertificatesByLocation);
		assertEquals(2, foundCertificatesByLocation.size());
		
		SignatureWrapper signature2Wrapper = signatures.get(1);
		allFoundRevocationRefs = signature2Wrapper.foundRevocations().getRelatedRevocationRefs();
		assertNotNull(allFoundRevocationRefs);
		assertEquals(2, allFoundRevocationRefs.size());
		assertEquals(2, signature2Wrapper.foundRevocations().getRelatedRevocationData().size());
		assertEquals(0, signature2Wrapper.foundRevocations().getOrphanRevocationData().size());
		
	}
	
	private DiagnosticData validate(DSSDocument signedDocument) {
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signedDocument);
		validator.setCertificateVerifier(getOfflineCertificateVerifier());

		Reports reports = validator.validateDocument();
		DiagnosticData diagnosticData = reports.getDiagnosticData();

		List<String> signatureIdList = diagnosticData.getSignatureIdList();
		assertTrue(Utils.isCollectionNotEmpty(signatureIdList));
		for (String signatureId : signatureIdList) {
			assertTrue(diagnosticData.isBLevelTechnicallyValid(signatureId));
		}
		return diagnosticData;
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

}
