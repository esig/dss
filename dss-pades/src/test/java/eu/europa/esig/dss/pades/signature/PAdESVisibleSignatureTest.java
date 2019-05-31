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
import java.io.FileInputStream;
import java.io.IOException;
import java.util.Date;

import org.junit.Before;
import org.junit.Test;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.SignatureValue;
import eu.europa.esig.dss.ToBeSigned;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.SignatureImageParameters;
import eu.europa.esig.dss.pades.SignatureImageTextParameters;
import eu.europa.esig.dss.pades.SignatureImageTextParameters.SignerPosition;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.signature.PKIFactoryAccess;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.validation.reports.wrapper.DiagnosticData;

public class PAdESVisibleSignatureTest extends PKIFactoryAccess {

	private DocumentSignatureService<PAdESSignatureParameters> service;
	private PAdESSignatureParameters signatureParameters;
	private DSSDocument documentToSign;

	@Before
	public void init() throws Exception {
		documentToSign = new FileDocument(new File("src/test/resources/sample.pdf"));

		signatureParameters = new PAdESSignatureParameters();
		signatureParameters.bLevel().setSigningDate(new Date());
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);

		service = new PAdESService(getCompleteCertificateVerifier());
	}

	@Test
	public void testGeneratedTextOnly() throws IOException {
		SignatureImageParameters imageParameters = new SignatureImageParameters();
		SignatureImageTextParameters textParameters = new SignatureImageTextParameters();
		textParameters.setText("My signature");
		textParameters.setTextColor(Color.GREEN);
		imageParameters.setTextParameters(textParameters);
		signatureParameters.setSignatureImageParameters(imageParameters);

		signAndValidate();
	}

	@Test
	public void testGeneratedImageOnly() throws IOException {
		SignatureImageParameters imageParameters = new SignatureImageParameters();
		imageParameters.setImage(new FileDocument(new File("src/test/resources/small-red.jpg")));
		imageParameters.setxAxis(100);
		imageParameters.setyAxis(100);
		signatureParameters.setSignatureImageParameters(imageParameters);

		signAndValidate();
	}

	@Test
	public void testGeneratedImageOnlyPNG() throws IOException {
		SignatureImageParameters imageParameters = new SignatureImageParameters();
		imageParameters.setImage(new FileDocument(new File("src/test/resources/signature-image.png")));
		imageParameters.setxAxis(100);
		imageParameters.setyAxis(100);
		signatureParameters.setSignatureImageParameters(imageParameters);

		signAndValidate();
	}

	@Test
	public void testGeneratedImageOnlyPNGWithSize() throws IOException {
		SignatureImageParameters imageParameters = new SignatureImageParameters();
		imageParameters.setImage(new FileDocument(new File("src/test/resources/small-red.jpg")));
		imageParameters.setxAxis(100);
		imageParameters.setyAxis(100);
		imageParameters.setWidth(50);
		imageParameters.setHeight(50);
		signatureParameters.setSignatureImageParameters(imageParameters);

		signAndValidate();
	}

	@Test
	public void testGeneratedImagePNGWithText() throws IOException {
		SignatureImageParameters imageParameters = new SignatureImageParameters();
		imageParameters.setImage(new FileDocument(new File("src/test/resources/signature-image.png")));
		imageParameters.setxAxis(100);
		imageParameters.setyAxis(100);

		SignatureImageTextParameters textParameters = new SignatureImageTextParameters();
		textParameters.setText("My signature");
		textParameters.setTextColor(Color.GREEN);
		imageParameters.setTextParameters(textParameters);

		imageParameters.setZoom(150); // augments 50%
		signatureParameters.setSignatureImageParameters(imageParameters);
		signAndValidate();
	}

	@Test
	public void testGeneratedImagePNGWithTextOnTop() throws IOException {
		SignatureImageParameters imageParameters = new SignatureImageParameters();
		imageParameters.setImage(new FileDocument(new File("src/test/resources/signature-image.png")));
		imageParameters.setxAxis(100);
		imageParameters.setyAxis(100);

		SignatureImageTextParameters textParameters = new SignatureImageTextParameters();
		textParameters.setText("My signature");
		textParameters.setTextColor(Color.GREEN);
		textParameters.setSignerNamePosition(SignerPosition.TOP);
		imageParameters.setTextParameters(textParameters);

		signatureParameters.setSignatureImageParameters(imageParameters);
		signAndValidate();
	}

	@Test
	public void testGeneratedImageOnlyPngUnZoom() throws IOException {
		SignatureImageParameters imageParameters = new SignatureImageParameters();
		imageParameters.setImage(new FileDocument(new File("src/test/resources/signature-image.png")));
		imageParameters.setxAxis(100);
		imageParameters.setyAxis(100);
		imageParameters.setZoom(50); // reduces 50%
		signatureParameters.setSignatureImageParameters(imageParameters);

		signAndValidate();
	}

	@Test
	public void testGeneratedImageAndTextOnTop() throws IOException {
		SignatureImageParameters imageParameters = new SignatureImageParameters();
		imageParameters.setImage(new InMemoryDocument(new FileInputStream("src/test/resources/small-red.jpg"), "small-red.jpg"));
		imageParameters.setxAxis(200);
		imageParameters.setyAxis(300);
		SignatureImageTextParameters textParameters = new SignatureImageTextParameters();
		textParameters.setText("My signature");
		textParameters.setTextColor(Color.BLUE);
		textParameters.setFont(new Font("Arial", Font.BOLD, 15));
		textParameters.setSignerNamePosition(SignerPosition.TOP);
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
		imageParameters.getTextParameters().setSignerNamePosition(SignerPosition.RIGHT);
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
		imageParameters.setImage(new FileDocument(new File("src/test/resources/signature-image.png")));
		signAndValidate();

		// image and text on right and horizontal align is center with transparent colors with big image and vertical
		// align top
		imageParameters.setSignerTextImageVerticalAlignment(SignatureImageParameters.SignerTextImageVerticalAlignment.TOP);
		signAndValidate();

		// image and text on right and horizontal align is center with transparent colors with big image and vertical
		// align bottom
		imageParameters.setSignerTextImageVerticalAlignment(SignatureImageParameters.SignerTextImageVerticalAlignment.BOTTOM);
		signAndValidate();

		// image and text on left and horizontal align is center with transparent colors with big image and vertical
		// align bottom
		imageParameters.getTextParameters().setSignerNamePosition(SignerPosition.LEFT);
		signAndValidate();

		// image and text on left and horizontal align is center with transparent colors and vertical align bottom
		imageParameters.setImage(new FileDocument(new File("src/test/resources/small-red.jpg")));
		signAndValidate();
	}

	private SignatureImageParameters createSignatureImageParameters() {
		SignatureImageParameters imageParameters = new SignatureImageParameters();
		imageParameters.setImage(new FileDocument(new File("src/test/resources/small-red.jpg")));
		imageParameters.setxAxis(200);
		imageParameters.setyAxis(300);
		SignatureImageTextParameters textParameters = new SignatureImageTextParameters();
		textParameters.setText("My signature\nsecond line\nlong line is very long line with long text example this");
		textParameters.setTextColor(Color.BLUE);
		textParameters.setSignerNamePosition(SignerPosition.LEFT);
		imageParameters.setTextParameters(textParameters);

		return imageParameters;
	}

	private void signAndValidate() throws IOException {
		ToBeSigned dataToSign = service.getDataToSign(documentToSign, signatureParameters);
		SignatureValue signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
		DSSDocument signedDocument = service.signDocument(documentToSign, signatureParameters, signatureValue);

		// signedDocument.save("target/test.pdf");

		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signedDocument);
		validator.setCertificateVerifier(getCompleteCertificateVerifier());
		Reports reports = validator.validateDocument();

		DiagnosticData diagnosticData = reports.getDiagnosticData();
		assertTrue(diagnosticData.isBLevelTechnicallyValid(diagnosticData.getFirstSignatureId()));
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

}
