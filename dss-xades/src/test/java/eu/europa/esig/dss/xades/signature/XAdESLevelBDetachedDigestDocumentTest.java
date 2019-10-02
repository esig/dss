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
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;

import org.junit.Test;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignatureScope;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.enumerations.SignatureScopeType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DigestDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.test.signature.PKIFactoryAccess;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;

public class XAdESLevelBDetachedDigestDocumentTest extends PKIFactoryAccess {

	private static final String DOCUMENT_NAME = "test.text";
	private static final DigestAlgorithm USED_DIGEST = DigestAlgorithm.SHA256;

	@Test
	public void testWithCompleteDocument() {
		XAdESService service = getService();
		XAdESSignatureParameters params = getParams();
		DSSDocument completeDocument = getCompleteDocument();

		ToBeSigned toBeSigned = service.getDataToSign(completeDocument, params);
		SignatureValue signatureValue = getToken().sign(toBeSigned, params.getDigestAlgorithm(), getPrivateKeyEntry());
		DSSDocument signedDoc = service.signDocument(completeDocument, params, signatureValue);

		validate(signedDoc, completeDocument);
		validate(signedDoc, getDigestDocument());
		validateWrong(signedDoc);

		DSSDocument extendDocument = service.extendDocument(signedDoc, getExtendParams());
		DiagnosticData diagnosticData = validate(extendDocument, completeDocument);
		List<SignatureWrapper> signatures = diagnosticData.getSignatures();
		assertEquals(1, signatures.size());
		SignatureWrapper signatureWrapper = signatures.get(0);
		List<XmlSignatureScope> signatureScopes = signatureWrapper.getSignatureScopes();
		assertEquals(1, signatureScopes.size());
		XmlSignatureScope xmlSignatureScope = signatureScopes.get(0);
		assertEquals(SignatureScopeType.FULL, xmlSignatureScope.getScope());
		assertEquals(DOCUMENT_NAME, xmlSignatureScope.getName());
	}

	@Test
	public void testWithCompleteDocumentNoName() throws IOException {
		XAdESService service = getService();
		XAdESSignatureParameters params = getParams();
		DSSDocument completeDocumentNoName = getCompleteDocumentNoName();

		ToBeSigned toBeSigned = service.getDataToSign(completeDocumentNoName, params);
		SignatureValue signatureValue = getToken().sign(toBeSigned, params.getDigestAlgorithm(), getPrivateKeyEntry());
		DSSDocument signedDoc = service.signDocument(completeDocumentNoName, params, signatureValue);

		validate(signedDoc, completeDocumentNoName);
		validate(signedDoc, getDigestDocument());
		validateWrong(signedDoc);

		DSSDocument extendDocument = service.extendDocument(signedDoc, getExtendParams());
		DiagnosticData diagnosticData = validate(extendDocument, completeDocumentNoName);
		List<SignatureWrapper> signatures = diagnosticData.getSignatures();
		assertEquals(1, signatures.size());
		SignatureWrapper signatureWrapper = signatures.get(0);
		List<XmlSignatureScope> signatureScopes = signatureWrapper.getSignatureScopes();
		assertEquals(1, signatureScopes.size());
		XmlSignatureScope xmlSignatureScope = signatureScopes.get(0);
		assertEquals(SignatureScopeType.FULL, xmlSignatureScope.getScope());
		assertNull(xmlSignatureScope.getName());
	}

	@Test
	public void testWithDigestDocument() {
		XAdESService service = getService();
		XAdESSignatureParameters params = getParams();
		DSSDocument digestDocument = getDigestDocument();

		ToBeSigned toBeSigned = service.getDataToSign(digestDocument, params);
		SignatureValue signatureValue = getToken().sign(toBeSigned, params.getDigestAlgorithm(), getPrivateKeyEntry());
		DSSDocument signedDoc = service.signDocument(digestDocument, params, signatureValue);

		validate(signedDoc, digestDocument);
		validate(signedDoc, getCompleteDocument());
		validateWrong(signedDoc);

		DSSDocument extendDocument = service.extendDocument(signedDoc, getExtendParams());
		DiagnosticData diagnosticData = validate(extendDocument, digestDocument);
		List<SignatureWrapper> signatures = diagnosticData.getSignatures();
		assertEquals(1, signatures.size());
		SignatureWrapper signatureWrapper = signatures.get(0);
		List<XmlSignatureScope> signatureScopes = signatureWrapper.getSignatureScopes();
		assertEquals(1, signatureScopes.size());
		XmlSignatureScope xmlSignatureScope = signatureScopes.get(0);
		assertEquals(SignatureScopeType.DIGEST, xmlSignatureScope.getScope());
		assertNull(xmlSignatureScope.getName());
	}

	private DiagnosticData validate(DSSDocument signedDocument, DSSDocument original) {
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signedDocument);
		validator.setCertificateVerifier(getCompleteCertificateVerifier());
		validator.setDetachedContents(Arrays.asList(original));
		Reports reports = validator.validateDocument();

		DiagnosticData diagData = reports.getDiagnosticData();
		assertTrue(diagData.isBLevelTechnicallyValid(diagData.getFirstSignatureId()));
		return diagData;
	}

	private void validateWrong(DSSDocument signedDocument) {
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signedDocument);
		validator.setCertificateVerifier(getCompleteCertificateVerifier());
		validator.setDetachedContents(Arrays.asList(getWrongDocument()));
		Reports reports = validator.validateDocument();

		DiagnosticData diagData = reports.getDiagnosticData();
		assertFalse(diagData.isBLevelTechnicallyValid(diagData.getFirstSignatureId()));
	}

	private XAdESService getService() {
		XAdESService service = new XAdESService(getCompleteCertificateVerifier());
		service.setTspSource(getGoodTsa());
		return service;
	}

	private XAdESSignatureParameters getParams() {
		XAdESSignatureParameters signatureParameters = new XAdESSignatureParameters();
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setDigestAlgorithm(USED_DIGEST);
		signatureParameters.setSignaturePackaging(SignaturePackaging.DETACHED);
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
		return signatureParameters;
	}

	private XAdESSignatureParameters getExtendParams() {
		XAdESSignatureParameters signatureParameters = new XAdESSignatureParameters();
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_LTA);
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
		DigestDocument digestDocument = new DigestDocument(USED_DIGEST, getCompleteDocument().getDigest(USED_DIGEST));
		return digestDocument;
	}

	private DSSDocument getWrongDocument() {
		return new InMemoryDocument("Bye World !".getBytes(), DOCUMENT_NAME);
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

}
