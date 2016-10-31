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

import static org.junit.Assert.assertTrue;

import java.awt.Color;
import java.awt.Font;
import java.io.File;
import java.io.IOException;
import java.util.Date;

import org.junit.Before;
import org.junit.Test;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.SignatureAlgorithm;
import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.SignaturePackaging;
import eu.europa.esig.dss.SignatureValue;
import eu.europa.esig.dss.ToBeSigned;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.SignatureImageParameters;
import eu.europa.esig.dss.pades.SignatureImageTextParameters;
import eu.europa.esig.dss.pades.SignatureImageTextParameters.SignerPosition;
import eu.europa.esig.dss.pades.TextAlignment;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.test.TestUtils;
import eu.europa.esig.dss.test.gen.CertificateService;
import eu.europa.esig.dss.test.mock.MockPrivateKeyEntry;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.validation.reports.wrapper.DiagnosticData;

public class PAdESVisibleSignatureTest {
	public static final String DEFAULT_SIGNATURE_IMAGE = "src/test/resources/small-red.jpg";

	private DocumentSignatureService<PAdESSignatureParameters> service;
	private PAdESSignatureParameters signatureParameters;
	private DSSDocument documentToSign;
	private MockPrivateKeyEntry privateKeyEntry;

	@Before
	public void init() throws Exception {
		documentToSign = new FileDocument(new File("src/test/resources/sample.pdf"));

		CertificateService certificateService = new CertificateService();
		privateKeyEntry = certificateService.generateCertificateChain(SignatureAlgorithm.RSA_SHA256);

		signatureParameters = new PAdESSignatureParameters();
		signatureParameters.bLevel().setSigningDate(new Date());
		signatureParameters.setSigningCertificate(privateKeyEntry.getCertificate());
		signatureParameters.setCertificateChain(privateKeyEntry.getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
		signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);

		CertificateVerifier certificateVerifier = new CommonCertificateVerifier();
		service = new PAdESService(certificateVerifier);
	}

	@Test
	public void testGeneratedTextOnly() throws IOException {
		SignatureImageParameters imageParameters = new SignatureImageParameters();
		SignatureImageTextParameters textParameters = new SignatureImageTextParameters();
		textParameters.setText("My signature");
		textParameters.setTextColor(Color.GREEN);
		imageParameters.setTextParameters(textParameters);
		signatureParameters.setImageParameters(imageParameters);

		signAndValidate();
	}

	@Test
	public void testGeneratedImageOnly() throws IOException {
		SignatureImageParameters imageParameters = new SignatureImageParameters();
		imageParameters.setImage(new File(DEFAULT_SIGNATURE_IMAGE));
		imageParameters.setxAxis(100);
		imageParameters.setyAxis(100);
		signatureParameters.setImageParameters(imageParameters);

		signAndValidate();
	}

	@Test
	public void testGeneratedImageAndTextOnTop() throws IOException {
		testGeneratedImageAndTextOnTop("My signature", TextAlignment.HORIZONTAL_LEFT);
	}

	@Test
	public void testGeneratedImageAndMultilineTextOnTop() throws IOException {
		testGeneratedImageAndTextOnTop("X\nxx\nxXx", TextAlignment.HORIZONTAL_CENTER);
	}

	private void testGeneratedImageAndTextOnTop(String text, TextAlignment horizontalAlignment) throws IOException {
		SignatureImageParameters imageParameters = new SignatureImageParameters();
		imageParameters.setImage(new File(DEFAULT_SIGNATURE_IMAGE));
		imageParameters.setxAxis(100);
		imageParameters.setyAxis(100);
		SignatureImageTextParameters textParameters = new SignatureImageTextParameters();
		textParameters.setText(text);
		textParameters.setTextColor(Color.BLUE);
		textParameters.setFont(new Font("Arial", Font.BOLD, 15));
		textParameters.setSignerNamePosition(SignerPosition.TOP);
		textParameters.setSignerNameHorizontalAlignment(horizontalAlignment);
		imageParameters.setTextParameters(textParameters);
		signatureParameters.setImageParameters(imageParameters);

		signAndValidate("target/test-top-" + horizontalAlignment.name() + ".pdf");
	}

	@Test
	public void testGeneratedImageAndTextOnLeft() throws IOException {
		testGeneratedImageAndTextOnLeft("My signature", TextAlignment.HORIZONTAL_LEFT);
	}

	@Test
	public void testGeneratedImageAndMultilineTextOnLeft() throws IOException {
		testGeneratedImageAndTextOnLeft("x\nxx\nxxX\nxx\nx", TextAlignment.HORIZONTAL_LEFT);
	}

	private void testGeneratedImageAndTextOnLeft(String text, TextAlignment horizontalAlignment) throws IOException {
		SignatureImageParameters imageParameters = new SignatureImageParameters();
		imageParameters.setImage(new File(DEFAULT_SIGNATURE_IMAGE));
		imageParameters.setxAxis(100);
		imageParameters.setyAxis(100);
		SignatureImageTextParameters textParameters = new SignatureImageTextParameters();
		textParameters.setText(text);
		textParameters.setTextColor(Color.BLUE);
		textParameters.setSignerNamePosition(SignerPosition.LEFT);
		textParameters.setSignerNameHorizontalAlignment(horizontalAlignment);
		imageParameters.setTextParameters(textParameters);
		signatureParameters.setImageParameters(imageParameters);

		signAndValidate("target/test-left-" + horizontalAlignment.name() + ".pdf");
	}

	private void signAndValidate() throws IOException {
		signAndValidate(null);
	}

	private void signAndValidate(String signedPdfFilename) throws IOException {
		ToBeSigned dataToSign = service.getDataToSign(documentToSign, signatureParameters);
		SignatureValue signatureValue = TestUtils.sign(SignatureAlgorithm.RSA_SHA256, privateKeyEntry, dataToSign);
		DSSDocument signedDocument = service.signDocument(documentToSign, signatureParameters, signatureValue);

//		if (signedPdfFilename != null) signedDocument.save(signedPdfFilename);

		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signedDocument);
		validator.setCertificateVerifier(new CommonCertificateVerifier());
		Reports reports = validator.validateDocument();

		DiagnosticData diagnosticData = reports.getDiagnosticData();
		assertTrue(diagnosticData.isBLevelTechnicallyValid(diagnosticData.getFirstSignatureId()));
	}
}
