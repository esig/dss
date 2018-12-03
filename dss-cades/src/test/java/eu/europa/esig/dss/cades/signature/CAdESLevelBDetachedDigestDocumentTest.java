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

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.Arrays;

import org.junit.Test;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.DigestDocument;
import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.SignaturePackaging;
import eu.europa.esig.dss.SignatureValue;
import eu.europa.esig.dss.ToBeSigned;
import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.signature.PKIFactoryAccess;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.validation.reports.wrapper.DiagnosticData;

public class CAdESLevelBDetachedDigestDocumentTest extends PKIFactoryAccess {

	private static final String DOCUMENT_NAME = "test.text";
	private static final DigestAlgorithm USED_DIGEST = DigestAlgorithm.SHA256;

	@Test
	public void testWithCompleteDocument() {
		CAdESService service = getService();
		CAdESSignatureParameters params = getParams();
		DSSDocument completeDocument = getCompleteDocument();

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
	public void testWithDigestDocument() {
		CAdESService service = getService();
		CAdESSignatureParameters params = getParams();
		DSSDocument digestDocument = getDigestDocument();

		ToBeSigned toBeSigned = service.getDataToSign(digestDocument, params);
		SignatureValue signatureValue = getToken().sign(toBeSigned, params.getDigestAlgorithm(), getPrivateKeyEntry());
		DSSDocument signedDoc = service.signDocument(digestDocument, params, signatureValue);

		validate(signedDoc, digestDocument);
		validate(signedDoc, getCompleteDocument());
		validateWrong(signedDoc);

		DSSDocument extendDocument = service.extendDocument(signedDoc, getExtendParams());
		validate(extendDocument, digestDocument);
	}

	private void validate(DSSDocument signedDocument, DSSDocument original) {
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signedDocument);
		validator.setCertificateVerifier(getCompleteCertificateVerifier());
		validator.setDetachedContents(Arrays.asList(original));
		Reports reports = validator.validateDocument();

		DiagnosticData diagData = reports.getDiagnosticData();
		assertTrue(diagData.isBLevelTechnicallyValid(diagData.getFirstSignatureId()));
	}

	private void validateWrong(DSSDocument signedDocument) {
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signedDocument);
		validator.setCertificateVerifier(getCompleteCertificateVerifier());
		validator.setDetachedContents(Arrays.asList(getWrongDocument()));
		Reports reports = validator.validateDocument();

		DiagnosticData diagData = reports.getDiagnosticData();
		assertFalse(diagData.isBLevelTechnicallyValid(diagData.getFirstSignatureId()));
	}

	private CAdESService getService() {
		CAdESService service = new CAdESService(getCompleteCertificateVerifier());
		service.setTspSource(getGoodTsa());
		return service;
	}

	private CAdESSignatureParameters getParams() {
		CAdESSignatureParameters signatureParameters = new CAdESSignatureParameters();
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setDigestAlgorithm(USED_DIGEST);
		signatureParameters.setSignaturePackaging(SignaturePackaging.DETACHED);
		signatureParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_B);
		return signatureParameters;
	}

	private CAdESSignatureParameters getExtendParams() {
		CAdESSignatureParameters signatureParameters = new CAdESSignatureParameters();
		signatureParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_T);
		signatureParameters.setDetachedContents(Arrays.asList(getDigestDocument()));
		return signatureParameters;
	}

	private DSSDocument getCompleteDocument() {
		return new InMemoryDocument("Hello World !".getBytes(), DOCUMENT_NAME);
	}

	private DSSDocument getDigestDocument() {
		DigestDocument digestDocument = new DigestDocument();
		// digestDocument.setName(DOCUMENT_NAME);
		digestDocument.addDigest(USED_DIGEST, Utils.toBase64(DSSUtils.digest(USED_DIGEST, getCompleteDocument())));
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
