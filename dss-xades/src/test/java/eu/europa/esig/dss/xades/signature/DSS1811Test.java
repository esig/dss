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

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DigestDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.test.PKIFactoryAccess;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import org.junit.jupiter.api.Test;

import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DSS1811Test extends PKIFactoryAccess {

	private static final String DOCUMENT_NAME = "test.text";
	private static final DigestAlgorithm USED_DIGEST = DigestAlgorithm.SHA512;

	@Test
	void testWithCompleteDocument() {
		XAdESService service = getService();
		XAdESSignatureParameters params = getParams();
		DSSDocument completeDocument = getCompleteDocument();

		assertEquals(params.getReferenceDigestAlgorithm(), params.getDigestAlgorithm());

		ToBeSigned toBeSigned = service.getDataToSign(completeDocument, params);
		SignatureValue signatureValue = getToken().sign(toBeSigned, params.getDigestAlgorithm(), getPrivateKeyEntry());
		DSSDocument signedDoc = service.signDocument(completeDocument, params, signatureValue);

		validate(signedDoc, completeDocument);
		validate(signedDoc, getDigestDocument());
		validateWrong(signedDoc);

		DSSDocument extendDocument = service.extendDocument(signedDoc, getExtendParams());
		validate(extendDocument, completeDocument);
	}

	@Test
	void testWithCompleteDocumentNoName() {
		XAdESService service = getService();
		XAdESSignatureParameters params = getParams();
		DSSDocument completeDocumentNoName = getCompleteDocumentNoName();

		assertEquals(params.getReferenceDigestAlgorithm(), params.getDigestAlgorithm());

		ToBeSigned toBeSigned = service.getDataToSign(completeDocumentNoName, params);
		SignatureValue signatureValue = getToken().sign(toBeSigned, params.getDigestAlgorithm(), getPrivateKeyEntry());
		DSSDocument signedDoc = service.signDocument(completeDocumentNoName, params, signatureValue);

		validate(signedDoc, completeDocumentNoName);
		validate(signedDoc, getDigestDocument());
		validateWrong(signedDoc);

		DSSDocument extendDocument = service.extendDocument(signedDoc, getExtendParams());
		validate(extendDocument, completeDocumentNoName);
	}

	@Test
	void testWithDigestDocument() {
		XAdESService service = getService();
		XAdESSignatureParameters params = getParams();
		DSSDocument digestDocument = getDigestDocument();

		assertEquals(params.getReferenceDigestAlgorithm(), params.getDigestAlgorithm());

		ToBeSigned toBeSigned = service.getDataToSign(digestDocument, params);
		SignatureValue signatureValue = getToken().sign(toBeSigned, params.getDigestAlgorithm(), getPrivateKeyEntry());
		DSSDocument signedDoc = service.signDocument(digestDocument, params, signatureValue);

		validate(signedDoc, digestDocument);
		validate(signedDoc, getCompleteDocument());
		validateWrong(signedDoc);

		DSSDocument extendDocument = service.extendDocument(signedDoc, getExtendParams());
		validate(extendDocument, digestDocument);
	}

	@Test
	void alteredDigestAlgo() {
		// Changed digest algo for signed info
		DSSDocument signedDoc = new FileDocument("src/test/resources/validation/dss1811-multi-algo.xml");

		Reports reports = getReports(signedDoc, getDigestDocument());

		DiagnosticData diagData = reports.getDiagnosticData();
		SignatureWrapper signatureWrapper = diagData.getSignatureById(diagData.getFirstSignatureId());
		assertFalse(signatureWrapper.isBLevelTechnicallyValid());
		for (XmlDigestMatcher digestMatcher : signatureWrapper.getDigestMatchers()) {
			if (DigestMatcherType.REFERENCE == digestMatcher.getType()) {
				assertTrue(digestMatcher.isDataFound());
				assertTrue(digestMatcher.isDataIntact());
			} else {
				assertTrue(digestMatcher.isDataFound());
				assertFalse(digestMatcher.isDataIntact());
			}
		}

		reports = getReports(signedDoc, getCompleteDocument());

		diagData = reports.getDiagnosticData();
		signatureWrapper = diagData.getSignatureById(diagData.getFirstSignatureId());
		assertFalse(signatureWrapper.isBLevelTechnicallyValid());
		for (XmlDigestMatcher digestMatcher : signatureWrapper.getDigestMatchers()) {
			if (DigestMatcherType.REFERENCE == digestMatcher.getType()) {
				assertTrue(digestMatcher.isDataFound());
				assertTrue(digestMatcher.isDataIntact());
			} else {
				assertTrue(digestMatcher.isDataFound());
				assertFalse(digestMatcher.isDataIntact());
			}
		}
				

		reports = getReports(signedDoc, getDigestDocumentWrongDigestAlgo());
		
		diagData = reports.getDiagnosticData();
		signatureWrapper = diagData.getSignatureById(diagData.getFirstSignatureId());
		assertFalse(signatureWrapper.isBLevelTechnicallyValid());
		for (XmlDigestMatcher digestMatcher : signatureWrapper.getDigestMatchers()) {
			if (DigestMatcherType.REFERENCE == digestMatcher.getType()) {
				assertFalse(digestMatcher.isDataFound());
				assertFalse(digestMatcher.isDataIntact());
			} else {
				assertTrue(digestMatcher.isDataFound());
				assertFalse(digestMatcher.isDataIntact());
			}
		}

	}

	private void validate(DSSDocument signedDocument, DSSDocument original) {
		Reports reports = getReports(signedDocument, original);

		DiagnosticData diagData = reports.getDiagnosticData();
		SignatureWrapper signatureWrapper = diagData.getSignatureById(diagData.getFirstSignatureId());
		assertTrue(signatureWrapper.isBLevelTechnicallyValid());
		for (XmlDigestMatcher digestMatcher : signatureWrapper.getDigestMatchers()) {
			assertTrue(digestMatcher.isDataFound());
			assertTrue(digestMatcher.isDataIntact());
		}
	}

	private void validateWrong(DSSDocument signedDocument) {
		Reports reports = getReports(signedDocument, getWrongDocument());

		DiagnosticData diagData = reports.getDiagnosticData();
		assertFalse(diagData.isBLevelTechnicallyValid(diagData.getFirstSignatureId()));
	}

	private Reports getReports(DSSDocument signedDocument, DSSDocument detached) {
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signedDocument);
		validator.setCertificateVerifier(getOfflineCertificateVerifier());
		validator.setDetachedContents(Arrays.asList(detached));
		return validator.validateDocument();
	}

	private XAdESService getService() {
		XAdESService service = new XAdESService(getOfflineCertificateVerifier());
		service.setTspSource(getGoodTsa());
		return service;
	}

	private XAdESSignatureParameters getParams() {
		XAdESSignatureParameters signatureParameters = new XAdESSignatureParameters();
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setReferenceDigestAlgorithm(USED_DIGEST);
		signatureParameters.setSignaturePackaging(SignaturePackaging.DETACHED);
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
		return signatureParameters;
	}

	private XAdESSignatureParameters getExtendParams() {
		XAdESSignatureParameters signatureParameters = new XAdESSignatureParameters();
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_T);
		signatureParameters.setDetachedContents(Arrays.asList(getDigestDocument()));
		return signatureParameters;
	}

	private DSSDocument getCompleteDocument() {
		return new InMemoryDocument("Hello World !".getBytes(), DOCUMENT_NAME);
	}

	private DSSDocument getCompleteDocumentNoName() {
		return new InMemoryDocument("Hello World !".getBytes());
	}

	private DSSDocument getDigestDocument() {
		return new DigestDocument(USED_DIGEST, getCompleteDocument().getDigestValue(USED_DIGEST));
	}
	
	private DSSDocument getDigestDocumentWrongDigestAlgo() {
		return new DigestDocument(DigestAlgorithm.SHA1, getCompleteDocument().getDigestValue(DigestAlgorithm.SHA1));
	}

	private DSSDocument getWrongDocument() {
		return new InMemoryDocument("Bye World !".getBytes(), DOCUMENT_NAME);
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

}
