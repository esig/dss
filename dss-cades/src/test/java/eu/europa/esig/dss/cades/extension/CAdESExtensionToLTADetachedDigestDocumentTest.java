/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.cades.extension;

import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.cades.signature.CAdESService;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DigestDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.test.PKIFactoryAccess;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CAdESExtensionToLTADetachedDigestDocumentTest extends PKIFactoryAccess {
		
	private static final DigestAlgorithm digestAlgo = DigestAlgorithm.SHA512;

	@Test
	void testSignWithCompleteDocumentExtendWithCompleteDocument() {
		CAdESService service = getService();
		CAdESSignatureParameters parameters = getParams();
		DSSDocument completeDocumentNoName = getCompleteDocumentNoName();
		DSSDocument completeDocument = getCompleteDocument();
		DSSDocument digestDocument = getDigestDocument();
		
		ToBeSigned toBeSigned = service.getDataToSign(completeDocument, parameters);
		SignatureValue signatureValue = getToken().sign(toBeSigned, parameters.getDigestAlgorithm(), getPrivateKeyEntry());
		DSSDocument signedDoc = service.signDocument(completeDocument, parameters, signatureValue);

		validate(signedDoc, completeDocumentNoName);
		validate(signedDoc, completeDocument);
		validate(signedDoc, digestDocument);
		validateWrong(signedDoc);

		CAdESSignatureParameters extendParams = getExtendParams();
		extendParams.setDetachedContents(Arrays.asList(completeDocument));
		DSSDocument extendDocument = service.extendDocument(signedDoc, extendParams);
		
		validate(extendDocument, completeDocumentNoName);
		validate(extendDocument, completeDocument);
		validate(extendDocument, digestDocument);
		validateWrong(extendDocument);
	}
	
	@Test
	void testSignWithCompleteDocumentExtendWithDigest() {
		CAdESService service = getService();
		CAdESSignatureParameters parameters = getParams();
		DSSDocument completeDocumentNoName = getCompleteDocumentNoName();
		DSSDocument completeDocument = getCompleteDocument();
		DSSDocument digestDocument = getDigestDocument();
		
		ToBeSigned toBeSigned = service.getDataToSign(completeDocument, parameters);
		SignatureValue signatureValue = getToken().sign(toBeSigned, parameters.getDigestAlgorithm(), getPrivateKeyEntry());
		DSSDocument signedDoc = service.signDocument(completeDocument, parameters, signatureValue);

		validate(signedDoc, completeDocumentNoName);
		validate(signedDoc, completeDocument);
		validate(signedDoc, digestDocument);
		validateWrong(signedDoc);

		CAdESSignatureParameters extendParams = getExtendParams();
		extendParams.setDetachedContents(Arrays.asList(digestDocument));
		DSSDocument extendDocument = service.extendDocument(signedDoc, extendParams);
		
		validate(extendDocument, completeDocumentNoName);
		validate(extendDocument, completeDocument);
		validate(extendDocument, digestDocument);
		validateWrong(extendDocument);
	}
	
	@Test
	void testSignWithCompleteDocumentExtendWithCompleteDocumentNoName() {
		CAdESService service = getService();
		CAdESSignatureParameters parameters = getParams();
		DSSDocument completeDocumentNoName = getCompleteDocumentNoName();
		DSSDocument completeDocument = getCompleteDocument();
		DSSDocument digestDocument = getDigestDocument();
		
		ToBeSigned toBeSigned = service.getDataToSign(completeDocument, parameters);
		SignatureValue signatureValue = getToken().sign(toBeSigned, parameters.getDigestAlgorithm(), getPrivateKeyEntry());
		DSSDocument signedDoc = service.signDocument(completeDocument, parameters, signatureValue);

		validate(signedDoc, completeDocumentNoName);
		validate(signedDoc, completeDocument);
		validate(signedDoc, digestDocument);
		validateWrong(signedDoc);

		CAdESSignatureParameters extendParams = getExtendParams();
		extendParams.setDetachedContents(Arrays.asList(completeDocumentNoName));
		DSSDocument extendDocument = service.extendDocument(signedDoc, extendParams);
		
		validate(extendDocument, completeDocumentNoName);
		validate(extendDocument, completeDocument);
		validate(extendDocument, digestDocument);
		validateWrong(extendDocument);
	}

	@Test
	void testSignWithDigestExtendWithCompleteDocument() {
		CAdESService service = getService();
		CAdESSignatureParameters params = getParams();
		DSSDocument completeDocumentNoName = getCompleteDocumentNoName();
		DSSDocument completeDocument = getCompleteDocument();
		DSSDocument digestDocument = getDigestDocument();

		ToBeSigned toBeSigned = service.getDataToSign(digestDocument, params);
		SignatureValue signatureValue = getToken().sign(toBeSigned, params.getDigestAlgorithm(), getPrivateKeyEntry());
		DSSDocument signedDoc = service.signDocument(digestDocument, params, signatureValue);

		validate(signedDoc, completeDocumentNoName);
		validate(signedDoc, completeDocument);
		validate(signedDoc, digestDocument);
		validateWrong(signedDoc);

		CAdESSignatureParameters extendParams = getExtendParams();
		extendParams.setDetachedContents(Arrays.asList(completeDocument));
		DSSDocument extendDocument = service.extendDocument(signedDoc, extendParams);
		
		validate(extendDocument, completeDocumentNoName);
		validate(extendDocument, completeDocument);
		validate(extendDocument, digestDocument);
		validateWrong(extendDocument);
	}
	
	@Test
	void testSignWithDigestExtendWithCompleteDocumentNoName() {
		CAdESService service = getService();
		CAdESSignatureParameters params = getParams();
		DSSDocument completeDocumentNoName = getCompleteDocumentNoName();
		DSSDocument completeDocument = getCompleteDocument();
		DSSDocument digestDocument = getDigestDocument();

		ToBeSigned toBeSigned = service.getDataToSign(digestDocument, params);
		SignatureValue signatureValue = getToken().sign(toBeSigned, params.getDigestAlgorithm(), getPrivateKeyEntry());
		DSSDocument signedDoc = service.signDocument(digestDocument, params, signatureValue);

		validate(signedDoc, completeDocumentNoName);
		validate(signedDoc, completeDocument);
		validate(signedDoc, digestDocument);
		validateWrong(signedDoc);

		CAdESSignatureParameters extendParams = getExtendParams();
		extendParams.setDetachedContents(Arrays.asList(completeDocumentNoName));
		DSSDocument extendDocument = service.extendDocument(signedDoc, extendParams);
		
		validate(extendDocument, completeDocumentNoName);
		validate(extendDocument, completeDocument);
		validate(extendDocument, digestDocument);
		validateWrong(extendDocument);
	}
	
	@Test
	void testSignWithDigestExtendWithDigest() {
		CAdESService service = getService();
		CAdESSignatureParameters params = getParams();
		DSSDocument completeDocumentNoName = getCompleteDocumentNoName();
		DSSDocument completeDocument = getCompleteDocument();
		DSSDocument digestDocument = getDigestDocument();

		ToBeSigned toBeSigned = service.getDataToSign(digestDocument, params);
		SignatureValue signatureValue = getToken().sign(toBeSigned, params.getDigestAlgorithm(), getPrivateKeyEntry());
		DSSDocument signedDoc = service.signDocument(digestDocument, params, signatureValue);

		validate(signedDoc, completeDocumentNoName);
		validate(signedDoc, completeDocument);
		validate(signedDoc, digestDocument);
		validateWrong(signedDoc);


		CAdESSignatureParameters extendParams = getExtendParams();
		extendParams.setDetachedContents(Arrays.asList(digestDocument));
		DSSDocument extendDocument = service.extendDocument(signedDoc, extendParams);
		
		validate(extendDocument, completeDocumentNoName);
		validate(extendDocument, completeDocument);
		validate(extendDocument, digestDocument);
		validateWrong(extendDocument);
	}
	
	@Test
	void testSignWithCompleteDocumentNoNameExtendWithCompleteDocumentNoName() throws IOException {
		CAdESService service = getService();
		CAdESSignatureParameters params = getParams();
		DSSDocument completeDocumentNoName = getCompleteDocumentNoName();
		DSSDocument completeDocument = getCompleteDocument();
		DSSDocument digestDocument = getDigestDocument();

		ToBeSigned toBeSigned = service.getDataToSign(completeDocumentNoName, params);
		SignatureValue signatureValue = getToken().sign(toBeSigned, params.getDigestAlgorithm(), getPrivateKeyEntry());
		DSSDocument signedDoc = service.signDocument(completeDocumentNoName, params, signatureValue);

		validate(signedDoc, completeDocumentNoName);
		validate(signedDoc, completeDocument);
		validate(signedDoc, digestDocument);
		validateWrong(signedDoc);

		CAdESSignatureParameters extendParams = getExtendParams();
		extendParams.setDetachedContents(Arrays.asList(completeDocumentNoName));
		DSSDocument extendDocument = service.extendDocument(signedDoc, extendParams);
		
		validate(extendDocument, completeDocumentNoName);
		validate(extendDocument, completeDocument);
		validate(extendDocument, digestDocument);
		validateWrong(extendDocument);
	}
	
	@Test
	void testSignWithCompleteDocumentNoNameExtendWithCompleteDocument() throws IOException {
		CAdESService service = getService();
		CAdESSignatureParameters params = getParams();
		DSSDocument completeDocumentNoName = getCompleteDocumentNoName();
		DSSDocument completeDocument = getCompleteDocument();
		DSSDocument digestDocument = getDigestDocument();

		ToBeSigned toBeSigned = service.getDataToSign(completeDocumentNoName, params);
		SignatureValue signatureValue = getToken().sign(toBeSigned, params.getDigestAlgorithm(), getPrivateKeyEntry());
		DSSDocument signedDoc = service.signDocument(completeDocumentNoName, params, signatureValue);

		validate(signedDoc, completeDocumentNoName);
		validate(signedDoc, completeDocument);
		validate(signedDoc, digestDocument);
		validateWrong(signedDoc);

		CAdESSignatureParameters extendParams = getExtendParams();
		extendParams.setDetachedContents(Arrays.asList(completeDocument));
		DSSDocument extendDocument = service.extendDocument(signedDoc, extendParams);
		
		validate(extendDocument, completeDocumentNoName);
		validate(extendDocument, completeDocument);
		validate(extendDocument, digestDocument);
		validateWrong(extendDocument);
	}
	
	@Test
	void testSignWithCompleteDocumentNoNameExtendWithDigest() throws IOException {
		CAdESService service = getService();
		CAdESSignatureParameters params = getParams();
		DSSDocument completeDocumentNoName = getCompleteDocumentNoName();
		DSSDocument completeDocument = getCompleteDocument();
		DSSDocument digestDocument = getDigestDocument();

		ToBeSigned toBeSigned = service.getDataToSign(completeDocumentNoName, params);
		SignatureValue signatureValue = getToken().sign(toBeSigned, params.getDigestAlgorithm(), getPrivateKeyEntry());
		DSSDocument signedDoc = service.signDocument(completeDocumentNoName, params, signatureValue);

		validate(signedDoc, completeDocumentNoName);
		validate(signedDoc, completeDocument);
		validate(signedDoc, digestDocument);
		validateWrong(signedDoc);

		CAdESSignatureParameters extendParams = getExtendParams();
		extendParams.setDetachedContents(Arrays.asList(digestDocument));
		DSSDocument extendDocument = service.extendDocument(signedDoc, extendParams);
		
		validate(extendDocument, completeDocumentNoName);
		validate(extendDocument, completeDocument);
		validate(extendDocument, digestDocument);
		validateWrong(extendDocument);
	}
	
	private void validate(DSSDocument signedDocument, DSSDocument original) {
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signedDocument);
		validator.setCertificateVerifier(getCompleteCertificateVerifier());
		validator.setDetachedContents(Arrays.asList(original));
		Reports reports = validator.validateDocument();
		
		DiagnosticData diagData = reports.getDiagnosticData();
		assertTrue(diagData.isBLevelTechnicallyValid(diagData.getFirstSignatureId()));
	
		List<TimestampWrapper> timestampList = diagData.getTimestampList();
		for (TimestampWrapper timestampWrapper : timestampList) {
			assertTrue(timestampWrapper.isMessageImprintDataFound());
			assertTrue(timestampWrapper.isMessageImprintDataIntact());
			assertTrue(timestampWrapper.isSignatureValid());
			assertTrue(timestampWrapper.isSignatureIntact());
		}
	}

	private void validateWrong(DSSDocument signedDocument) {
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signedDocument);
		validator.setCertificateVerifier(getCompleteCertificateVerifier());
		validator.setDetachedContents(Arrays.asList(getWrongDocument()));
		Reports reports = validator.validateDocument();

		DiagnosticData diagData = reports.getDiagnosticData();
		assertFalse(diagData.isBLevelTechnicallyValid(diagData.getFirstSignatureId()));
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}
	
	private CAdESService getService() {
		CAdESService service = new CAdESService(getCompleteCertificateVerifier());
		service.setTspSource(getGoodTsa());
		return service;
	}
	
	private CAdESSignatureParameters getParams() {
		CAdESSignatureParameters signatureParameters = new CAdESSignatureParameters();
		signatureParameters.bLevel().setSigningDate(new Date());
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.DETACHED);
		signatureParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_B);
		signatureParameters.setDigestAlgorithm(digestAlgo);
		return signatureParameters;
	}
	
	private CAdESSignatureParameters getExtendParams() {
		CAdESSignatureParameters signatureParameters = new CAdESSignatureParameters();
		signatureParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_LTA);
		return signatureParameters;
	}
	
	private DSSDocument getCompleteDocumentNoName() {
		return new InMemoryDocument("Hello World !".getBytes());
	}
	
	private DSSDocument getCompleteDocument() {
		return new InMemoryDocument("Hello World !".getBytes(), "test");
	}
	
	private DSSDocument getWrongDocument() {
		return new InMemoryDocument("Bye World !".getBytes(), "test");
	}

	private DSSDocument getDigestDocument() {
		return new DigestDocument(digestAlgo, getCompleteDocument().getDigestValue(digestAlgo));
	}

}
