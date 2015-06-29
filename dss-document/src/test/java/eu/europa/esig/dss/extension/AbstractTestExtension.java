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
package eu.europa.esig.dss.extension;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.security.GeneralSecurityException;
import java.security.Signature;

import org.junit.Test;

import eu.europa.esig.dss.AbstractSignatureParameters;
import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.SignatureAlgorithm;
import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.SignatureValue;
import eu.europa.esig.dss.ToBeSigned;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.test.mock.MockPrivateKeyEntry;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.report.DiagnosticData;
import eu.europa.esig.dss.validation.report.Reports;

public abstract class AbstractTestExtension<SP extends AbstractSignatureParameters> {

	protected abstract DSSDocument getSignedDocument() throws Exception;

	protected abstract SignatureLevel getOriginalSignatureLevel();

	protected abstract SignatureLevel getFinalSignatureLevel();

	/**
	 * This method is used in case of ASiC signatures
	 *
	 * @return
	 */
	protected SignatureLevel getOriginalUnderlyingSignatureLevel() {
		return getOriginalSignatureLevel();
	}

	/**
	 * This method is used in case of ASiC signatures
	 *
	 * @return
	 */
	protected SignatureLevel getFinalUnderlyingSignatureLevel() {
		return getFinalSignatureLevel();
	}

	protected abstract DocumentSignatureService<SP> getSignatureServiceToExtend() throws Exception;

	protected SignatureValue sign(SignatureAlgorithm algo, MockPrivateKeyEntry privateKey, ToBeSigned bytesToSign) throws GeneralSecurityException {
		final Signature signature = Signature.getInstance(algo.getJCEId());
		signature.initSign(privateKey.getPrivateKey());
		signature.update(bytesToSign.getBytes());
		final byte[] signatureValue = signature.sign();
		return new SignatureValue(algo, signatureValue);
	}

	@Test
	public void test() throws Exception {
		DSSDocument signedDocument = getSignedDocument();
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signedDocument);
		validator.setCertificateVerifier(new CommonCertificateVerifier());
		Reports reports = validator.validateDocument();

		DiagnosticData diagnosticData = reports.getDiagnosticData();

		checkOriginalLevel(diagnosticData);
		checkBLevelValid(diagnosticData);

		DSSDocument extendedDocument = extendSignature(signedDocument);

		assertNotNull(extendedDocument);
		assertNotNull(extendedDocument.getMimeType());
		assertNotNull(extendedDocument.getBytes());

		validator = SignedDocumentValidator.fromDocument(extendedDocument);
		validator.setCertificateVerifier(new CommonCertificateVerifier());
		reports = validator.validateDocument();

		diagnosticData = reports.getDiagnosticData();

		checkFinalLevel(diagnosticData);
		checkBLevelValid(diagnosticData);
		checkTLevelAndValid(diagnosticData);
	}

	private DSSDocument extendSignature(DSSDocument signedDocument) throws Exception {
		SP extensionParameters = getExtensionParameters();
		DocumentSignatureService<SP> service = getSignatureServiceToExtend();

		DSSDocument extendedDocument = service.extendDocument(signedDocument, extensionParameters);
		assertNotNull(extendedDocument);
		return extendedDocument;
	}


	protected abstract SP getExtensionParameters();

	private void checkOriginalLevel(DiagnosticData diagnosticData) {
		assertEquals(getOriginalUnderlyingSignatureLevel().name(), diagnosticData.getSignatureFormat(diagnosticData.getFirstSignatureId()));
	}

	private void checkFinalLevel(DiagnosticData diagnosticData) {
		assertEquals(getFinalUnderlyingSignatureLevel().name(), diagnosticData.getSignatureFormat(diagnosticData.getFirstSignatureId()));
	}

	private void checkBLevelValid(DiagnosticData diagnosticData) {
		assertTrue(diagnosticData.isBLevelTechnicallyValid(diagnosticData.getFirstSignatureId()));
	}

	private void checkTLevelAndValid(DiagnosticData diagnosticData) {
		assertTrue(diagnosticData.isThereTLevel(diagnosticData.getFirstSignatureId()));
		assertTrue(diagnosticData.isTLevelTechnicallyValid(diagnosticData.getFirstSignatureId()));
	}

}
