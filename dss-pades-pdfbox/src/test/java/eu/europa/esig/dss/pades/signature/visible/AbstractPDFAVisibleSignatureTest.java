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
package eu.europa.esig.dss.pades.signature.visible;

import eu.europa.esig.dss.alert.exception.AlertException;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.SignatureFieldParameters;
import eu.europa.esig.dss.pades.SignatureImageParameters;
import eu.europa.esig.dss.pades.SignatureImageTextParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.pdf.IPdfObjFactory;
import eu.europa.esig.dss.pdfa.validation.PDFADocumentValidator;
import eu.europa.esig.dss.test.PKIFactoryAccess;
import eu.europa.esig.dss.test.UnmarshallingTester;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.awt.Color;
import java.io.IOException;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public abstract class AbstractPDFAVisibleSignatureTest extends PKIFactoryAccess {

	protected PAdESService service;
	protected PAdESSignatureParameters signatureParameters;
	protected DSSDocument documentToSign;

	@BeforeEach
	public void init() throws Exception {
		signatureParameters = new PAdESSignatureParameters();
		signatureParameters.bLevel().setSigningDate(new Date());
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);

		service = new PAdESService(getOfflineCertificateVerifier());
		setCustomFactory();
	}

	/**
	 * Set a custom instance of {@link IPdfObjFactory}
	 */
	protected abstract void setCustomFactory();

	@Test
	public void testGeneratedTextOnly() throws IOException {
		documentToSign = new InMemoryDocument(getClass().getResourceAsStream("/not_signed_pdfa.pdf"));

		SignatureImageParameters imageParameters = new SignatureImageParameters();
		SignatureImageTextParameters textParameters = new SignatureImageTextParameters();
		textParameters.setText("My signature");
		textParameters.setTextColor(Color.GREEN);
		imageParameters.setTextParameters(textParameters);
		signatureParameters.setImageParameters(imageParameters);

		signAndValidate("PDF/A-1B", true);
	}

	@Test
	public void testGeneratedTextWithOnlyAlpha() throws IOException {
		documentToSign = new InMemoryDocument(getClass().getResourceAsStream("/not_signed_pdfa.pdf"));

		SignatureImageParameters imageParameters = new SignatureImageParameters();
		SignatureImageTextParameters textParameters = new SignatureImageTextParameters();
		textParameters.setText("My signature");
		textParameters.setTextColor(new Color(0, 255, 0, 100));
		imageParameters.setTextParameters(textParameters);
		signatureParameters.setImageParameters(imageParameters);

		signAndValidate("PDF/A-1B", false);
	}

	@Test
	public void testGeneratedImageOnly() throws IOException {
		documentToSign = new InMemoryDocument(getClass().getResourceAsStream("/not_signed_pdfa.pdf"));

		SignatureImageParameters imageParameters = new SignatureImageParameters();
		imageParameters.setImage(new InMemoryDocument(getClass().getResourceAsStream("/small-red.jpg"), "small-red.jpg", MimeTypeEnum.JPEG));
		
		SignatureFieldParameters fieldParameters = new SignatureFieldParameters();
		fieldParameters.setOriginX(100);
		fieldParameters.setOriginY(100);
		imageParameters.setFieldParameters(fieldParameters);
		
		signatureParameters.setImageParameters(imageParameters);

		signAndValidate("PDF/A-1B", true);
	}

	@Test
	public void testGeneratedImageOnlyPNG() throws IOException {
		documentToSign = new InMemoryDocument(getClass().getResourceAsStream("/not_signed_pdfa.pdf"));

		SignatureImageParameters imageParameters = new SignatureImageParameters();
		// PNG with ALPHA
		imageParameters.setImage(new InMemoryDocument(getClass().getResourceAsStream("/signature-image.png"), "signature-image.png", MimeTypeEnum.PNG));
		
		SignatureFieldParameters fieldParameters = new SignatureFieldParameters();
		fieldParameters.setOriginX(100);
		fieldParameters.setOriginY(100);
		imageParameters.setFieldParameters(fieldParameters);
		
		signatureParameters.setImageParameters(imageParameters);

		Exception exception = assertThrows(AlertException.class, () ->
				signAndValidate("PDF/A-1B", false));
		assertTrue(exception.getMessage().contains("The new signature field position is outside the page dimensions!"));

		fieldParameters.setWidth(400);
		fieldParameters.setHeight(200);
		signAndValidate("PDF/A-1B", false);
	}

	@Test
	public void testGeneratedTextToDocWithoutColorSpaceWithColor() throws IOException {
		documentToSign = new InMemoryDocument(getClass().getResourceAsStream("/testdoc.pdf"));

		SignatureImageParameters imageParameters = new SignatureImageParameters();
		SignatureImageTextParameters textParameters = new SignatureImageTextParameters();
		textParameters.setBackgroundColor(Color.YELLOW);
		textParameters.setText("My signature");
		textParameters.setTextColor(Color.GREEN);
		imageParameters.setTextParameters(textParameters);
		signatureParameters.setImageParameters(imageParameters);

		signAndValidate("PDF/A-2U", true);
	}

	@Test
	public void testGeneratedTextToDocWithoutColorSpaceWithoutColor() throws IOException {
		documentToSign = new InMemoryDocument(getClass().getResourceAsStream("/testdoc.pdf"));

		SignatureImageParameters imageParameters = new SignatureImageParameters();
		SignatureImageTextParameters textParameters = new SignatureImageTextParameters();
		textParameters.setBackgroundColor(null);
		textParameters.setText("My signature");
		textParameters.setTextColor(null);
		imageParameters.setTextParameters(textParameters);
		signatureParameters.setImageParameters(imageParameters);

		signAndValidate("PDF/A-2U", true);
	}

	@Test
	public void testGeneratedTextToRGBDocWithColor() throws IOException {
		documentToSign = new InMemoryDocument(getClass().getResourceAsStream("/pdfa2a-rgb.pdf"));

		SignatureImageParameters imageParameters = new SignatureImageParameters();
		SignatureImageTextParameters textParameters = new SignatureImageTextParameters();
		textParameters.setBackgroundColor(Color.YELLOW);
		textParameters.setText("My signature");
		textParameters.setTextColor(Color.GREEN);
		imageParameters.setTextParameters(textParameters);
		signatureParameters.setImageParameters(imageParameters);

		signAndValidate("PDF/A-2A", true);
	}

	@Test
	public void testGeneratedTextToGrayDocWithColor() throws IOException {
		documentToSign = new InMemoryDocument(getClass().getResourceAsStream("/pdfa2u-gray.pdf"));

		SignatureImageParameters imageParameters = new SignatureImageParameters();
		SignatureImageTextParameters textParameters = new SignatureImageTextParameters();
		textParameters.setBackgroundColor(Color.YELLOW);
		textParameters.setText("My signature");
		textParameters.setTextColor(Color.GREEN);
		imageParameters.setTextParameters(textParameters);
		signatureParameters.setImageParameters(imageParameters);

		signAndValidate("PDF/A-2U", false);
	}

	@Test
	public void testAddGrayscaleImageToRGBDoc() throws IOException {
		documentToSign = new InMemoryDocument(getClass().getResourceAsStream("/pdfa2a-rgb.pdf"));

		SignatureImageParameters imageParameters = new SignatureImageParameters();
		imageParameters.setImage(new InMemoryDocument(getClass().getResourceAsStream("/grayscale_image.png"), "grayscale_image.png", MimeType.PNG));

		SignatureFieldParameters fieldParameters = new SignatureFieldParameters();
		fieldParameters.setOriginX(100);
		fieldParameters.setOriginY(100);
		imageParameters.setFieldParameters(fieldParameters);

		signatureParameters.setImageParameters(imageParameters);

		signAndValidate("PDF/A-2A", true);
	}

	@Test
	public void testAddGrayscaleImageToNonProfileDoc() throws IOException {
		documentToSign = new InMemoryDocument(getClass().getResourceAsStream("/testdoc.pdf"));

		SignatureImageParameters imageParameters = new SignatureImageParameters();
		imageParameters.setImage(new InMemoryDocument(getClass().getResourceAsStream("/grayscale_image.png"), "grayscale_image.png", MimeType.PNG));

		SignatureFieldParameters fieldParameters = new SignatureFieldParameters();
		fieldParameters.setOriginX(100);
		fieldParameters.setOriginY(100);
		imageParameters.setFieldParameters(fieldParameters);

		signatureParameters.setImageParameters(imageParameters);

		signAndValidate("PDF/A-2U", true);
	}

	protected void signAndValidate(String expectedPdfAProfile, boolean expectedValidPDFA) throws IOException {
		ToBeSigned dataToSign = service.getDataToSign(documentToSign, signatureParameters);
		SignatureValue signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
		DSSDocument signedDocument = service.signDocument(documentToSign, signatureParameters, signatureValue);

		// signedDocument.save("target/test.pdf");

		SignedDocumentValidator validator = new PDFADocumentValidator(signedDocument);
		validator.setCertificateVerifier(getOfflineCertificateVerifier());
		Reports reports = validator.validateDocument();

		DiagnosticData diagnosticData = reports.getDiagnosticData();
		assertTrue(diagnosticData.isBLevelTechnicallyValid(diagnosticData.getFirstSignatureId()));

		assertTrue(diagnosticData.isPDFAValidationPerformed());
		assertEquals(expectedPdfAProfile, diagnosticData.getPDFAProfileId());
		assertEquals(expectedValidPDFA, diagnosticData.isPDFACompliant(), diagnosticData.getPDFAValidationErrors().toString());
		assertEquals(expectedValidPDFA, Utils.isCollectionEmpty(diagnosticData.getPDFAValidationErrors()));

		UnmarshallingTester.unmarshallXmlReports(reports);
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

}
