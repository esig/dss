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

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.awt.Color;
import java.io.IOException;
import java.util.Date;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.MimeType;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.pades.DSSFileFont;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.SignatureImageParameters;
import eu.europa.esig.dss.pades.SignatureImageTextParameters;
import eu.europa.esig.dss.pades.SignatureImageTextParameters.SignerTextPosition;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.pdf.IPdfObjFactory;
import eu.europa.esig.dss.test.signature.PKIFactoryAccess;
import eu.europa.esig.dss.validation.DefaultDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;

public class PAdESVisibleCombinationTextAndImageSignatureTest extends PKIFactoryAccess {

	protected PAdESService service;
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

		service = new PAdESService(getCompleteCertificateVerifier());
		setCustomFactory();
	}

	/**
	 * Set a custom instance of {@link IPdfObjFactory}
	 */
	protected void setCustomFactory() {
	}

	@Test
	public void testGeneratedImagePNGWithText() throws IOException {
		SignatureImageParameters imageParameters = new SignatureImageParameters();
		imageParameters.setImage(getPngPicture());
		imageParameters.setxAxis(100);
		imageParameters.setyAxis(100);

		SignatureImageTextParameters textParameters = new SignatureImageTextParameters();
		textParameters.setText("My signature");
		textParameters.setTextColor(Color.GREEN);
		imageParameters.setTextParameters(textParameters);

		imageParameters.setZoom(50); // reduces 50%
		signatureParameters.setSignatureImageParameters(imageParameters);
		signAndValidate();
	}

	@Test
	public void testGeneratedImagePNGWithTextOnTop() throws IOException {
		SignatureImageParameters imageParameters = new SignatureImageParameters();
		imageParameters.setImage(getPngPicture());
		imageParameters.setxAxis(100);
		imageParameters.setyAxis(100);

		SignatureImageTextParameters textParameters = new SignatureImageTextParameters();
		textParameters.setText("My signature");
		textParameters.setTextColor(Color.GREEN);
		textParameters.setSignerTextPosition(SignerTextPosition.TOP);
		imageParameters.setTextParameters(textParameters);

		signatureParameters.setSignatureImageParameters(imageParameters);
		signAndValidate();
	}

	@Test
	public void testGeneratedImageAndTextOnTop() throws IOException {
		SignatureImageParameters imageParameters = new SignatureImageParameters();
		imageParameters.setImage(getSmallRedJPG());
		imageParameters.setxAxis(200);
		imageParameters.setyAxis(300);
		SignatureImageTextParameters textParameters = new SignatureImageTextParameters();
		textParameters.setText("My signature");
		textParameters.setTextColor(Color.BLUE);
		textParameters.setFont(new DSSFileFont(getClass().getResourceAsStream("/fonts/OpenSansBold.ttf")));
		textParameters.setSize(15);
		textParameters.setSignerTextPosition(SignerTextPosition.TOP);
		imageParameters.setTextParameters(textParameters);
		signatureParameters.setSignatureImageParameters(imageParameters);

		signAndValidate();
	}

	@Test
	public void testGeneratedImageWithText() throws IOException {
		SignatureImageParameters imageParameters = createSignatureImageParameters();
		signatureParameters.setSignatureImageParameters(imageParameters);
		// image and text on left
		signAndValidate();

		// image and text on right
		imageParameters.getTextParameters().setSignerTextPosition(SignerTextPosition.RIGHT);
		signAndValidate();

		// image and text on right and horizontal align is right
		imageParameters.getTextParameters().setSignerTextHorizontalAlignment(SignatureImageTextParameters.SignerTextHorizontalAlignment.RIGHT);
		signAndValidate();

		// image and text on right and horizontal align is center
		imageParameters.getTextParameters().setSignerTextHorizontalAlignment(SignatureImageTextParameters.SignerTextHorizontalAlignment.CENTER);
		signAndValidate();

		// image and text on right and horizontal align is center with transparent colors
		Color transparent = new Color(0, 0, 0, 0.25f);
		imageParameters.getTextParameters().setBackgroundColor(transparent);
		imageParameters.getTextParameters().setTextColor(new Color(0.5f, 0.2f, 0.8f, 0.5f));
		imageParameters.setBackgroundColor(transparent);
		imageParameters.setxAxis(10);
		imageParameters.setyAxis(10);
		signAndValidate();

		// image and text on right and horizontal align is center with transparent colors with big image
		imageParameters.setImage(getPngPicture());
		signAndValidate();

		// image and text on right and horizontal align is center with transparent colors with big image and vertical
		// align top
		imageParameters.getTextParameters().setSignerTextVerticalAlignment(SignatureImageTextParameters.SignerTextVerticalAlignment.TOP);
		signAndValidate();

		// image and text on right and horizontal align is center with transparent colors with big image and vertical
		// align bottom
		imageParameters.getTextParameters().setSignerTextVerticalAlignment(SignatureImageTextParameters.SignerTextVerticalAlignment.BOTTOM);
		signAndValidate();

		// image and text on left and horizontal align is center with transparent colors with big image and vertical
		// align bottom
		imageParameters.getTextParameters().setSignerTextPosition(SignerTextPosition.LEFT);
		signAndValidate();

		// image and text on left and horizontal align is center with transparent colors and vertical align bottom
		imageParameters.setImage(getSmallRedJPG());
		signAndValidate();
	}

	private SignatureImageParameters createSignatureImageParameters() {
		SignatureImageParameters imageParameters = new SignatureImageParameters();
		imageParameters.setImage(getSmallRedJPG());
		imageParameters.setxAxis(200);
		imageParameters.setyAxis(300);
		SignatureImageTextParameters textParameters = new SignatureImageTextParameters();
		textParameters.setText("My signature\nsecond line\nlong line is very long line with long text example this");
		textParameters.setTextColor(Color.BLUE);
		textParameters.setSignerTextPosition(SignerTextPosition.LEFT);
		imageParameters.setTextParameters(textParameters);

		return imageParameters;
	}

	private void signAndValidate() throws IOException {
		ToBeSigned dataToSign = service.getDataToSign(documentToSign, signatureParameters);
		SignatureValue signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
		DSSDocument signedDocument = service.signDocument(documentToSign, signatureParameters, signatureValue);

		signedDocument.save("target/test.pdf");

		DefaultDocumentValidator validator = DefaultDocumentValidator.fromDocument(signedDocument);
		validator.setCertificateVerifier(getCompleteCertificateVerifier());
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
		return new InMemoryDocument(getClass().getResourceAsStream("/signature-image.png"), "signature-image.png", MimeType.PNG);
	}

}
