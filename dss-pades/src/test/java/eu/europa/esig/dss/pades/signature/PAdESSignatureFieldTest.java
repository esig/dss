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
package eu.europa.esig.dss.pades.signature;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.awt.Color;
import java.io.File;
import java.io.IOException;
import java.util.Date;

import org.junit.Before;
import org.junit.Test;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.SignatureAlgorithm;
import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.SignatureValue;
import eu.europa.esig.dss.ToBeSigned;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.SignatureFieldParameters;
import eu.europa.esig.dss.pades.SignatureImageParameters;
import eu.europa.esig.dss.pades.SignatureImageTextParameters;
import eu.europa.esig.dss.test.TestUtils;
import eu.europa.esig.dss.test.gen.CertificateService;
import eu.europa.esig.dss.test.mock.MockPrivateKeyEntry;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.validation.reports.wrapper.DiagnosticData;

public class PAdESSignatureFieldTest {

	private PAdESService service;
	private PAdESSignatureParameters signatureParameters;
	private MockPrivateKeyEntry privateKeyEntry;

	@Before
	public void init() throws Exception {

		CertificateService certificateService = new CertificateService();
		privateKeyEntry = certificateService.generateCertificateChain(SignatureAlgorithm.RSA_SHA256);

		signatureParameters = new PAdESSignatureParameters();
		signatureParameters.bLevel().setSigningDate(new Date());
		signatureParameters.setSigningCertificate(privateKeyEntry.getCertificate());
		signatureParameters.setCertificateChain(privateKeyEntry.getCertificateChain());
		signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);

		SignatureImageParameters imageParameters = new SignatureImageParameters();
		SignatureImageTextParameters textParameters = new SignatureImageTextParameters();
		textParameters.setText("My signature");
		textParameters.setTextColor(Color.GREEN);
		imageParameters.setTextParameters(textParameters);
		signatureParameters.setImageParameters(imageParameters);

		CertificateVerifier certificateVerifier = new CommonCertificateVerifier();
		service = new PAdESService(certificateVerifier);
	}

	@Test
	public void testGeneratedTextOnly() throws IOException {

		signatureParameters.setSignatureFieldId("Signature1");

		DSSDocument documentToSign = new FileDocument(new File("src/test/resources/doc.pdf"));
		signAndValidate(documentToSign);
	}

	@Test
	public void testSignTwice() throws IOException {

		signatureParameters.setSignatureFieldId("Signature1");

		DSSDocument documentToSign = new FileDocument(new File("src/test/resources/doc.pdf"));
		DSSDocument doc = signAndValidate(documentToSign);
		assertNotNull(doc);

		SignatureFieldParameters parameters = new SignatureFieldParameters();
		parameters.setName("test");
		parameters.setOriginX(10);
		parameters.setOriginY(10);
		parameters.setHeight(50);
		parameters.setWidth(50);
		DSSDocument doc2 = service.addNewSignatureField(doc, parameters);
		assertNotNull(doc2);

		signatureParameters.setSignatureFieldId("test");

		DSSDocument doc3 = signAndValidate(doc2);
		assertNotNull(doc3);
	}

	@Test(expected = DSSException.class)
	public void testSignTwiceSameField() throws IOException {

		signatureParameters.setSignatureFieldId("Signature1");

		DSSDocument documentToSign = new FileDocument(new File("src/test/resources/doc.pdf"));
		DSSDocument doc = signAndValidate(documentToSign);
		assertNotNull(doc);

		signAndValidate(doc);
	}

	@Test(expected = DSSException.class)
	public void testFieldNotFound() throws IOException {

		signatureParameters.setSignatureFieldId("not-found");

		DSSDocument documentToSign = new FileDocument(new File("src/test/resources/doc.pdf"));
		signAndValidate(documentToSign);
	}

	private DSSDocument signAndValidate(DSSDocument documentToSign) throws IOException {
		ToBeSigned dataToSign = service.getDataToSign(documentToSign, signatureParameters);
		SignatureValue signatureValue = TestUtils.sign(SignatureAlgorithm.RSA_SHA256, privateKeyEntry, dataToSign);
		DSSDocument signedDocument = service.signDocument(documentToSign, signatureParameters, signatureValue);

		// signedDocument.save("target/test.pdf");

		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signedDocument);
		validator.setCertificateVerifier(new CommonCertificateVerifier());
		Reports reports = validator.validateDocument();

		DiagnosticData diagnosticData = reports.getDiagnosticData();
		assertTrue(diagnosticData.isBLevelTechnicallyValid(diagnosticData.getFirstSignatureId()));

		return signedDocument;
	}

}
