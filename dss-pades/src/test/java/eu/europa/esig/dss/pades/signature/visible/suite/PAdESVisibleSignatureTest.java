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
package eu.europa.esig.dss.pades.signature.visible.suite;

import eu.europa.esig.dss.alert.exception.AlertException;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignerTextHorizontalAlignment;
import eu.europa.esig.dss.enumerations.SignerTextPosition;
import eu.europa.esig.dss.enumerations.SignerTextVerticalAlignment;
import eu.europa.esig.dss.enumerations.VisualSignatureAlignmentHorizontal;
import eu.europa.esig.dss.enumerations.VisualSignatureAlignmentVertical;
import eu.europa.esig.dss.enumerations.VisualSignatureRotation;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.MimeType;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.pades.DSSFileFont;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.PAdESTimestampParameters;
import eu.europa.esig.dss.pades.SignatureFieldParameters;
import eu.europa.esig.dss.pades.SignatureImageParameters;
import eu.europa.esig.dss.pades.SignatureImageTextParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.test.PKIFactoryAccess;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.awt.Color;
import java.io.IOException;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class PAdESVisibleSignatureTest extends PKIFactoryAccess {

	private DocumentSignatureService<PAdESSignatureParameters, PAdESTimestampParameters> service;
	private PAdESSignatureParameters signatureParameters;
	private DSSDocument documentToSign;

	@BeforeEach
	public void init() throws Exception {
		documentToSign = new InMemoryDocument(getClass().getResourceAsStream("/sample.pdf"));

		signatureParameters = new PAdESSignatureParameters();
		signatureParameters.bLevel().setSigningDate(new Date());
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);

		service = new PAdESService(getOfflineCertificateVerifier());
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
		imageParameters.setImage(getSmallRedJPG());

		SignatureFieldParameters fieldParameters = new SignatureFieldParameters();
		fieldParameters.setOriginX(100);
		fieldParameters.setOriginY(100);
		imageParameters.setFieldParameters(fieldParameters);

		signatureParameters.setImageParameters(imageParameters);

		signAndValidate();
	}

	@Test
	public void testGeneratedImageOnlyPNG() throws IOException {
		SignatureImageParameters imageParameters = new SignatureImageParameters();
		imageParameters.setImage(getPngPicture());

		SignatureFieldParameters fieldParameters = new SignatureFieldParameters();
		fieldParameters.setOriginX(100);
		fieldParameters.setOriginY(100);
		imageParameters.setFieldParameters(fieldParameters);

		signatureParameters.setImageParameters(imageParameters);

		Exception exception = assertThrows(AlertException.class, () -> signAndValidate());
		assertTrue(exception.getMessage().contains("The new signature field position is outside the page dimensions!"));

		fieldParameters.setWidth(400);
		fieldParameters.setHeight(200);
		signAndValidate();
	}

	@Test
	public void testGeneratedImageOnlyPNGWithSize() throws IOException {
		SignatureImageParameters imageParameters = new SignatureImageParameters();
		imageParameters.setImage(getSmallRedJPG());

		SignatureFieldParameters fieldParameters = new SignatureFieldParameters();
		fieldParameters.setOriginX(100);
		fieldParameters.setOriginY(100);
		fieldParameters.setWidth(50);
		fieldParameters.setHeight(50);
		imageParameters.setFieldParameters(fieldParameters);

		signatureParameters.setImageParameters(imageParameters);

		signAndValidate();
	}

	@Test
	public void testGeneratedImageOnlyPngAndZoom() throws IOException {
		SignatureImageParameters imageParameters = new SignatureImageParameters();
		imageParameters.setImage(getPngPicture());

		SignatureFieldParameters fieldParameters = new SignatureFieldParameters();
		fieldParameters.setOriginX(100);
		fieldParameters.setOriginY(100);
		imageParameters.setFieldParameters(fieldParameters);

		imageParameters.setZoom(50); // reduces 50%
		signatureParameters.setImageParameters(imageParameters);

		signAndValidate();
	}

	@Test
	public void testCMYKPicture() throws IOException {
		SignatureImageParameters imageParameters = new SignatureImageParameters();
		imageParameters.setImage(getCMYKPicture());

		SignatureFieldParameters fieldParameters = new SignatureFieldParameters();
		fieldParameters.setOriginX(100);
		fieldParameters.setOriginY(100);
		imageParameters.setFieldParameters(fieldParameters);

		signatureParameters.setImageParameters(imageParameters);

		signAndValidate();
	}

	@Test
	public void dss2090Test() throws IOException {
		String signature = "Some long signature text with\nmultiple\nnewlines in them\nfor testing";

		SignatureImageParameters imageParams = new SignatureImageParameters();
		imageParams.setAlignmentHorizontal(VisualSignatureAlignmentHorizontal.LEFT);
		imageParams.setAlignmentVertical(VisualSignatureAlignmentVertical.TOP);
		imageParams.setRotation(VisualSignatureRotation.AUTOMATIC);

		SignatureFieldParameters fieldParameters = new SignatureFieldParameters();
		fieldParameters.setOriginX(71);
		fieldParameters.setOriginY(71);
		imageParams.setFieldParameters(fieldParameters);

		SignatureImageTextParameters textParameters = new SignatureImageTextParameters();
		DSSFileFont fileFont = DSSFileFont.initializeDefault();
		fileFont.setSize(10);
		textParameters.setFont(fileFont);
		textParameters.setTextColor(Color.BLACK);
		textParameters.setBackgroundColor(Color.WHITE);
		textParameters.setPadding(0f);
		textParameters.setSignerTextVerticalAlignment(SignerTextVerticalAlignment.TOP);
		textParameters.setSignerTextHorizontalAlignment(SignerTextHorizontalAlignment.LEFT);
		textParameters.setSignerTextPosition(SignerTextPosition.TOP);
		textParameters.setText(signature);
		imageParams.setTextParameters(textParameters);

		signatureParameters.setImageParameters(imageParams);

		signAndValidate();
	}

	@Test
	public void dss2227Test() throws IOException {
		String signature = "Signature 1\nSignature 12345";

		SignatureImageParameters imageParams = new SignatureImageParameters();
		SignatureFieldParameters fieldParameters = new SignatureFieldParameters();
		fieldParameters.setWidth(100);
		fieldParameters.setHeight(100);
		imageParams.setFieldParameters(fieldParameters);

		SignatureImageTextParameters textParameters = new SignatureImageTextParameters();
		textParameters.setSignerTextPosition(SignerTextPosition.TOP);
		textParameters.setText(signature);
		textParameters.setBackgroundColor(Color.PINK);
		imageParams.setTextParameters(textParameters);

		signatureParameters.setImageParameters(imageParams);

		signAndValidate();
	}

	@Test
	public void textOnBottomTest() throws IOException {
		String signature = "Signature 1\nSignature 12345";

		SignatureImageParameters imageParams = new SignatureImageParameters();
		SignatureFieldParameters fieldParameters = new SignatureFieldParameters();
		fieldParameters.setOriginX(100);
		fieldParameters.setOriginY(100);
		fieldParameters.setHeight(100);
		imageParams.setFieldParameters(fieldParameters);

		SignatureImageTextParameters textParameters = new SignatureImageTextParameters();
		textParameters.setSignerTextPosition(SignerTextPosition.BOTTOM);
		textParameters.setSignerTextHorizontalAlignment(SignerTextHorizontalAlignment.RIGHT);
		textParameters.setBackgroundColor(Color.PINK);
		textParameters.setPadding(10);
		textParameters.setText(signature);
		imageParams.setTextParameters(textParameters);

		signatureParameters.setImageParameters(imageParams);

		signAndValidate();
	}

	private void signAndValidate() {
		ToBeSigned dataToSign = service.getDataToSign(documentToSign, signatureParameters);
		SignatureValue signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(),
				getPrivateKeyEntry());
		DSSDocument signedDocument = service.signDocument(documentToSign, signatureParameters, signatureValue);

		// signedDocument.save("target/test.pdf");

		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signedDocument);
		validator.setCertificateVerifier(getOfflineCertificateVerifier());
		Reports reports = validator.validateDocument();

		DiagnosticData diagnosticData = reports.getDiagnosticData();
		assertTrue(diagnosticData.isBLevelTechnicallyValid(diagnosticData.getFirstSignatureId()));
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

	private DSSDocument getSmallRedJPG() {
		return new InMemoryDocument(getClass().getResourceAsStream("/small-red.jpg"), "small-red.jpg", MimeType.JPEG);
	}

	private DSSDocument getPngPicture() {
		return new InMemoryDocument(getClass().getResourceAsStream("/signature-image.png"), "signature-image.png",
				MimeType.PNG);
	}

	private DSSDocument getCMYKPicture() {
		return new InMemoryDocument(getClass().getResourceAsStream("/cmyk.jpg"), "cmyk.jpg", MimeType.JPEG);
	}

}
